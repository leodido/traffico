import("core.project.project")
import("lib.detect.check_cxsnippets")

-- get sourcefiles
function _get_programs(target_name)
    local programs = {}
    for _, target in pairs(project.targets()) do
        if target:is_enabled() and target:name() == target_name then
            -- print(target:autogendir())
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
    local source_gendir = path.absolute(project.target(source_target):autogendir())
    if not source_gendir then
        raise("could not obtain the autogendir of the source target")
    end

    target:set("configdir", target:autogendir())

    --import("lib.detect.check_cxsnippets")
    --utils.dump(check_cxsnippets("void test() {(unsigned long)&((struct block_ip_bpf*)0)->rodata;}", {includes = {path.absolute("build/.gens/bpf/linux/x86_64/release/block_ip.skel.h")}}))

    local configfile_template = "api.$progname.h.in"
    local configfile_template_path = path.join(target:scriptdir(), configfile_template)

    local programs = _get_programs(source_target)
    for _, p in ipairs(programs) do
        --print(p)
        local progname = string.match(path.basename(p), "(.+)%..+$")
        local confname = string.gsub(configfile_template, "%$(%w+)", { progname = progname })
        local tempconf = path.join(os.tmpdir(), confname)
        os.tryrm(tempconf)
        os.cp(configfile_template_path, tempconf)

        local skelpath = path.join(source_gendir, progname .. ".skel.h")
        local has_rodata = check_cxsnippets("void test() {&((struct ".. progname .. "_bpf*)0)->rodata;}", {includes = skelpath}) and 1 or 0
        local rodata_name = ""
        if has_rodata then
            rodata_name = string.sub(progname, 0, 9)
        end

        target:add("configfiles", tempconf, {
            variables = {
                PROGNAME = progname, OPERATION = "attach__", PROGNAME_HAS_RODATA = has_rodata, ROMAP_NAME = rodata_name
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

    local programs = {}
    table.insert(programs, "0")
    for _, v in ipairs(vars) do
        table.insert(programs, v.variables.PROGNAME)
    end
    table.sort(programs)
    v["PROGRAMS_AS_SYMBOLS"] = 'program_' .. table.concat(programs, ", program_")
    v["PROGRAMS_AS_STRINGS"] = '"' .. table.concat(programs, '", "') .. '"'
    v["PROGRAMS_OPS_AS_SYMBOLS"] = op .. table.concat(programs, ', ' .. op)
    table.remove(programs, 1)
    v["PROGRAMS_DESCRIPTION"] = '"  - ' .. table.concat(programs, '\\n  - ') .. '"'

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
