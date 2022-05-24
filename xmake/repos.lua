if os.getenv("CODESPACES") then
    -- fetch locally
    add_repositories("local-repo ../xmake-repo")
end