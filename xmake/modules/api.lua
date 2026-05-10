import("core.project.project")

-- Build and runtime metadata for every user-facing BPF program.
--
-- Each entry controls:
--   input   - rodata union field name (nil if the program takes no input)
--   multi   - true when the input is an array (ethertypes, protos)
--   chainable - true when the program may appear in --chain
--
-- The standalone template uses input/multi for rodata layout.
-- The chain template uses chainable to decide which programs get a
-- generated case in load_chain_program() and appear in
-- program_supports_chaining().
--
-- Every non-internal BPF program MUST have an entry here.
-- Missing entries cause a build failure (see _get_metadata below).
local program_metadata = {
    allow_dns        = { input = "ip",          multi = false, chainable = true  },
    allow_ethertype  = { input = "ethertypes",  multi = true,  chainable = true  },
    allow_ipv4       = { input = "ip",          multi = false, chainable = true  },
    allow_port       = { input = "port",        multi = false, chainable = true  },
    allow_proto      = { input = "protos",      multi = true,  chainable = true  },
    block_ipv4       = { input = "ip",          multi = false, chainable = false },
    block_port       = { input = "port",        multi = false, chainable = false },
    block_private_ipv4 = {                      multi = false, chainable = false },
    nop              = {                        multi = false, chainable = false },
}

-- Internal BPF programs that are not user-facing.
-- These are compiled and get skeletons but are excluded from the
-- program list, enum, and dispatch table.
local internal_programs = {
    dispatcher = true,
}

-- Look up and validate metadata for a program.
-- Raises on missing entries or invalid field types so that omitting
-- chainable (or any other required field) is a build failure.
local function _get_metadata(progname)
    if internal_programs[progname] then
        return nil
    end
    local meta = program_metadata[progname]
    if type(meta) ~= "table" then
        raise("program '%s' has no table entry in program_metadata; add one to xmake/modules/api.lua", progname)
    end
    if type(meta.chainable) ~= "boolean" then
        raise("program '%s' must declare chainable = true or false in program_metadata", progname)
    end
    if meta.input ~= nil and type(meta.input) ~= "string" then
        raise("program '%s' metadata input must be a string or nil", progname)
    end
    if meta.multi ~= nil and type(meta.multi) ~= "boolean" then
        raise("program '%s' metadata multi must be true or false", progname)
    end
    return {
        input = meta.input,
        multi = meta.multi or false,
        chainable = meta.chainable,
    }
end

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
        local meta = _get_metadata(progname)
        local input_field = meta and meta.input or nil
        local is_multi = meta and meta.multi or false
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

--- Generate per-program chain case fragments from chain.$progname.h.in.
--- Only programs with chainable = true in program_metadata are included.
function gen_chain(target, source_target)
    if not target then
        raise("could not configure target")
    end

    target:set("configdir", target:autogendir())

    local configfile_template = "chain.$progname.h.in"
    local configfile_template_path = path.join(target:scriptdir(), configfile_template)

    local programs = _get_programs(source_target)
    for _, p in ipairs(programs) do
        local progname = string.match(path.basename(p), "(.+)%..+$")
        local meta = _get_metadata(progname)
        if not meta or not meta.chainable then
            goto continue
        end

        local confname = string.gsub(configfile_template, "%$(%w+)", { progname = progname })
        local tempconf = path.join(os.tmpdir(), confname)
        os.tryrm(tempconf)
        os.cp(configfile_template_path, tempconf)

        local input_field = meta.input
        local has_rodata = input_field and 1 or 0

        target:add("configfiles", tempconf, {
            variables = {
                PROGNAME = progname,
                PROGNAME_WITH_RODATA = has_rodata,
                PROGNAME_INPUT_FIELD = input_field or "",
            }
        })

        ::continue::
    end
end

--- Assemble generated chain case fragments into chain.h via chain.h.in.
function chain(target, components_target)
    if not target then
        raise("could not configure target")
    end

    local gendir = target:autogendir()
    target:add("includedirs", gendir, { public = true })
    target:set("configdir", gendir)

    local v = {}

    local _, components, vars = project.target(components_target):configfiles()

    -- Build skeleton includes, case blocks, and supports-check from
    -- the generated chain fragments.
    local includes = {}
    local cases = {}
    local supports = {}

    for i, pv in ipairs(vars) do
        local progname = pv.variables.PROGNAME
        table.insert(includes, '#include "' .. progname .. '.skel.h"')
        table.insert(cases, io.readfile(components[i]))
        table.insert(supports, "program == program_" .. progname)
    end

    table.sort(includes)
    table.sort(supports)

    v["CHAIN_SKELETON_INCLUDES"] = table.concat(includes, "\n")
    v["CHAIN_CASES"] = table.concat(cases, "\n")
    v["CHAIN_SUPPORTS_CHECK"] =
        #supports > 0 and table.concat(supports, " ||\n           ") or "false"

    local configfile = path.join(target:scriptdir(), "chain.h.in")
    target:add("configfiles", configfile, { variables = v })
end
