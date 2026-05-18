import("core.project.project")

-- Build and runtime metadata for every user-facing BPF program.
--
-- Each entry controls:
--   input     - userspace config/chain input field (nil if the program takes no input)
--   bpf_value - BPF rodata value field for programs with input
--   bpf_count - BPF rodata count field for multi-value programs
--   multi     - true when the input is an array (ethertypes, protos)
--   chainable - true when the program may appear in --chain
--   layer     - l2/l3/l4 for chainable programs
--
-- The standalone template uses input/multi/bpf_* for typed rodata writes.
-- The chain template uses chainable to decide which programs get a
-- generated case in load_chain_program() and appear in
-- program_supports_chaining(). The chain validator uses layer to
-- enforce L2 -> L3 -> L4 composition.
--
-- Every non-internal BPF program MUST have an entry here.
-- Missing entries cause a build failure (see _get_metadata below).
local program_metadata = {
    allow_dns = {
        input = "ip", bpf_value = "input",
        multi = false, chainable = true, layer = "l4",
    },
    allow_ethertype = {
        input = "ethertypes", bpf_value = "allowed", bpf_count = "num_allowed",
        multi = true, chainable = true, layer = "l2",
    },
    allow_ipv4 = {
        input = "ip", bpf_value = "input",
        multi = false, chainable = true, layer = "l3",
    },
    allow_port = {
        input = "port", bpf_value = "input",
        multi = false, chainable = true, layer = "l4",
    },
    allow_proto = {
        input = "protos", bpf_value = "allowed", bpf_count = "num_allowed",
        multi = true, chainable = true, layer = "l3",
    },
    block_ipv4 = {
        input = "ip", bpf_value = "input",
        multi = false, chainable = false,
    },
    block_port = {
        input = "port", bpf_value = "input",
        multi = false, chainable = false,
    },
    block_private_ipv4 = {
        multi = false, chainable = false,
    },
    nop = {
        multi = false, chainable = false,
    },
}

-- Internal BPF programs that are not user-facing.
-- These are compiled and get skeletons but are excluded from the
-- program list, enum, and dispatch table.
local internal_programs = {
    dispatcher = true,
    intent = true,
}

local config_input_fields = {
    ethertypes = true,
    ip = true,
    port = true,
    protos = true,
}

local reserved_bpf_rodata_fields = {
    chained = true,
    slot = true,
}

local function _is_c_identifier(value)
    return type(value) == "string" and value:match("^[A-Za-z_][A-Za-z0-9_]*$") ~= nil
end

local function _validate_bpf_field(progname, field_name, field_value)
    if not _is_c_identifier(field_value) then
        raise("program '%s' metadata %s must be a non-empty C identifier", progname, field_name)
    end
    if reserved_bpf_rodata_fields[field_value] then
        raise("program '%s' metadata %s must not use reserved rodata field '%s'",
              progname, field_name, field_value)
    end
end

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
    if meta.input ~= nil and not config_input_fields[meta.input] then
        raise("program '%s' metadata input must be one of ethertypes, ip, port, or protos", progname)
    end
    if meta.multi ~= nil and type(meta.multi) ~= "boolean" then
        raise("program '%s' metadata multi must be true or false", progname)
    end
    local multi = meta.multi or false
    local valid_layers = { l2 = true, l3 = true, l4 = true }
    if meta.input == nil and meta.bpf_value ~= nil then
        raise("program '%s' without input must not declare bpf_value in program_metadata", progname)
    end
    if meta.input ~= nil then
        if type(meta.bpf_value) ~= "string" then
            raise("program '%s' with input must declare bpf_value in program_metadata", progname)
        end
        _validate_bpf_field(progname, "bpf_value", meta.bpf_value)
    end
    if multi and meta.input == nil then
        raise("program '%s' with multi = true must declare input in program_metadata", progname)
    end
    if multi and type(meta.bpf_count) ~= "string" then
        raise("program '%s' with multi = true must declare bpf_count in program_metadata", progname)
    end
    if multi then
        _validate_bpf_field(progname, "bpf_count", meta.bpf_count)
    end
    if multi and meta.bpf_value == meta.bpf_count then
        raise("program '%s' metadata bpf_value and bpf_count must be distinct", progname)
    end
    if not multi and meta.bpf_count ~= nil then
        raise("program '%s' with multi = false must not declare bpf_count in program_metadata", progname)
    end
    if meta.chainable then
        if type(meta.layer) ~= "string" then
            raise("program '%s' with chainable = true must declare layer in program_metadata", progname)
        end
        if not valid_layers[meta.layer] then
            raise("program '%s' metadata layer must be one of l2, l3, or l4", progname)
        end
    elseif meta.layer ~= nil and not valid_layers[meta.layer] then
        raise("program '%s' metadata layer must be one of l2, l3, or l4", progname)
    end
    return {
        input = meta.input,
        multi = multi,
        chainable = meta.chainable,
        bpf_value = meta.bpf_value,
        bpf_count = meta.bpf_count,
        layer = meta.layer,
    }
end

local function _standalone_rodata_assignment(meta)
    if not meta or not meta.input then
        return "    // No rodata input for this program."
    end

    if meta.multi then
        return string.format([[
    // Set read-only data through typed skeleton fields before load.
    if (conf->has_input)
    {
        memcpy((void *)obj->rodata->%s,
               conf->input.%s.values,
               sizeof(conf->input.%s.values));
        obj->rodata->%s = conf->input.%s.count;
        log_out(conf, "done: setting rodata input\n");
    }]], meta.bpf_value, meta.input, meta.input, meta.bpf_count, meta.input)
    end

    return string.format([[
    // Set read-only data through typed skeleton fields before load.
    if (conf->has_input)
    {
        obj->rodata->%s = conf->input.%s;
        log_out(conf, "done: setting rodata input\n");
    }]], meta.bpf_value, meta.input)
end

local function _chain_input_assignment(meta)
    if not meta.input then
        return "        // No chain input rodata for this program."
    end

    if meta.multi then
        return string.format([[
        if (entry->has_input)
        {
            memcpy((void *)obj->rodata->%s,
                   entry->input.%s.values,
                   sizeof(entry->input.%s.values));
            obj->rodata->%s = entry->input.%s.count;
        }]], meta.bpf_value, meta.input, meta.input, meta.bpf_count, meta.input)
    end

    return string.format([[
        if (entry->has_input)
        {
            obj->rodata->%s = entry->input.%s;
        }]], meta.bpf_value, meta.input)
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
        local has_rodata = input_field and 1 or 0

        target:add("configfiles", tempconf, {
            variables = {
                PROGNAME = progname,
                OPERATION = "attach__",
                PROGNAME_WITH_RODATA = has_rodata,
                PROGNAME_RODATA_ASSIGNMENT = _standalone_rodata_assignment(meta),
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

        target:add("configfiles", tempconf, {
            variables = {
                PROGNAME = progname,
                PROGNAME_CHAIN_LAYER = meta.layer,
                PROGNAME_CHAIN_INPUT_ASSIGNMENT = _chain_input_assignment(meta),
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
    local layers = {}

    for i, pv in ipairs(vars) do
        local progname = pv.variables.PROGNAME
        local layer = pv.variables.PROGNAME_CHAIN_LAYER
        table.insert(includes, '#include "' .. progname .. '.skel.h"')
        table.insert(cases, io.readfile(components[i]))
        table.insert(supports, "program == program_" .. progname)
        table.insert(layers, "case program_" .. progname .. ": return CHAIN_LAYER_" .. string.upper(layer) .. ";")
    end

    table.sort(includes)
    table.sort(supports)
    table.sort(layers)

    v["CHAIN_SKELETON_INCLUDES"] = table.concat(includes, "\n")
    v["CHAIN_CASES"] = table.concat(cases, "\n")
    v["CHAIN_LAYER_CASES"] = table.concat(layers, "\n    ")
    v["CHAIN_SUPPORTS_CHECK"] =
        #supports > 0 and table.concat(supports, " ||\n           ") or "false"

    local configfile = path.join(target:scriptdir(), "chain.h.in")
    target:add("configfiles", configfile, { variables = v })
end

function intent_bpf(target)
    if not target then
        raise("could not configure target")
    end

    local gendir = target:autogendir()
    target:add("includedirs", gendir, { public = true })
    target:add("includedirs", target:scriptdir(), { public = true })
    target:set("configdir", gendir)

    local configfile = path.join(target:scriptdir(), "intent_bpf_loader.h.in")
    target:add("configfiles", configfile)
end
