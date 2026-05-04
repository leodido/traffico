import("core.project.project")

-- Map program names to their input union field in struct config.
-- Programs in this table have const volatile rodata that can be
-- configured at runtime via the input union in struct config.
--
-- Scalar programs use a plain string: "ip", "port".
-- Multi-value programs use a table: { field = "ethertypes", multi = true }.
-- The template uses PROGNAME_INPUT_FIELD for the union member name and
-- PROGNAME_IS_MULTI_VALUE to distinguish array inputs from scalars.
local input_fields = {
    allow_dns = "ip",
    allow_ethertype = { field = "ethertypes", multi = true },
    allow_ipv4 = "ip",
    allow_port = "port",
    allow_proto = { field = "protos", multi = true },
    block_ipv4 = "ip",
    block_port = "port",
}

-- Internal BPF programs that are not user-facing.
-- These are compiled and get skeletons but are excluded from the
-- program list, enum, and dispatch table.
local internal_programs = {
    dispatcher = true,
}

-- get sourcefiles
function _get_programs(target_name)
    local programs = {}
    for _, target in pairs(project.targets()) do
        if target:is_enabled() and target:name() == target_name then
            for _, src in pairs(target:sourcebatches()) do
                for _, f in ipairs(src.sourcefiles) do
                    local progname = string.match(path.basename(f), "(.+)%..+$")
                    if not internal_programs[progname] then
                        table.insert(programs, f)
                    end
                end
            end
        end
    end
    return programs
end

function gen(target, source_target)
    if not target then
        raise("could not configure target")
    end

    target:set("configdir", target:autogendir())

    local configfile_template = "api.$progname.h.in"
    local configfile_template_path = path.join(target:scriptdir(), configfile_template)

    local programs = _get_programs(source_target)
    for _, p in ipairs(programs) do
        local progname = string.match(path.basename(p), "(.+)%..+$")
        local confname = string.gsub(configfile_template, "%$(%w+)", { progname = progname })
        local tempconf = path.join(os.tmpdir(), confname)
        os.tryrm(tempconf)
        os.cp(configfile_template_path, tempconf)
        local raw = input_fields[progname]
        local input_field = nil
        local is_multi = false
        if type(raw) == "string" then
            input_field = raw
        elseif type(raw) == "table" then
            input_field = raw.field
            is_multi = raw.multi or false
        end
        local has_rodata = input_field and 1 or 0

        target:add("configfiles", tempconf, {
            variables = {
                PROGNAME = progname,
                OPERATION = "attach__",
                PROGNAME_WITH_RODATA = has_rodata,
                PROGNAME_INPUT_FIELD = input_field or "",
                PROGNAME_IS_MULTI_VALUE = is_multi and 1 or 0,
            }
        })
    end
end

function main(target, components_target, banner)
    if not target then
        raise("could not configure target")
    end

    local gendir = target:autogendir()
    target:add("includedirs", gendir, { public = true })
    target:set("configdir", gendir)

    local v = {}

    local _, components, vars = project.target(components_target):configfiles()
    local num_components = #components
    v["PROGRAMS_COUNT"] = num_components + 1

    local op = vars[1].variables.OPERATION
    v["OPERATION"] = op
    
    local descr = '"  - '
    local programs = {}
    table.insert(programs, "0")
    for i, pv in ipairs(vars) do
        table.insert(programs, pv.variables.PROGNAME)
        descr = descr .. pv.variables.PROGNAME .. (pv.variables.PROGNAME_WITH_RODATA == 1 and ' [input]' or '')
        if i ~= #vars then
            descr = descr .. '\\n  - '
        end
    end
    table.sort(programs)
    v["PROGRAMS_AS_SYMBOLS"] = 'program_' .. table.concat(programs, ", program_")
    v["PROGRAMS_AS_STRINGS"] = '"' .. table.concat(programs, '", "') .. '"'
    v["PROGRAMS_OPS_AS_SYMBOLS"] = op .. table.concat(programs, ', ' .. op)
    table.remove(programs, 1)
    v["PROGRAMS_DESCRIPTION"] = descr .. '"'

    local content = ""
    for i, c in ipairs(components) do
        if banner then
            content = content .. "/// " .. c .. "\n"
        end
        content = content .. io.readfile(c)
        if i < num_components then
            content = content .. "\n\n"
        end
    end
    v["API"] = content

    local configfile = path.join(target:scriptdir(), "api.h.in")
    target:add("configfiles", configfile, { variables = v })
end
