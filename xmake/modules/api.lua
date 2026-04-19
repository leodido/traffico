import("core.project.project")

-- Map program names to their input union field in struct config.
-- Programs in this table have const volatile rodata that can be
-- configured at runtime via the input union in struct config.
local input_fields = {
    block_ip = "ip",
    block_port = "port",
}

-- get sourcefiles
function _get_programs(target_name)
    local programs = {}
    for _, target in pairs(project.targets()) do
        if target:is_enabled() and target:name() == target_name then
            for _, src in pairs(target:sourcebatches()) do
                table.join2(programs, src.sourcefiles)
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
        local input_field = input_fields[progname]
        local has_rodata = input_field and 1 or 0

        target:add("configfiles", tempconf, {
            variables = {
                PROGNAME = progname,
                OPERATION = "attach__",
                PROGNAME_WITH_RODATA = has_rodata,
                PROGNAME_INPUT_FIELD = input_field or "",
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
