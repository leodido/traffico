import("core.project.project")

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
        target:add("configfiles", tempconf, { variables = { PROGNAME = progname } })
    end
end

function main(target, components_target, banner)
    if not target then
        raise("could not configure target")
    end

    local gendir = target:autogendir()
    target:add("includedirs", gendir, { public = true })
    target:set("configdir", gendir)

    local _, components = project.target(components_target):configfiles()
    local num_components = table.getn(components)

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

    local configfile = path.join(target:scriptdir(), "api.h.in")
    target:add("configfiles", configfile, { variables = { API = content } })
end
