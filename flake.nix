{
  description = "ai-control-layer (HackYeah 2026, Goldman Sachs task): policy gateway for agents, FastAPI + Next.js dashboard ";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python313;

          # Native libs that uv-installed wheels (numpy, opencv, torch, ...)
          # link against. Not in the NixOS loader path by default.
          # Same list as /etc/nixos/templates/python.
          pythonRuntimeLibs = with pkgs; [
            stdenv.cc.cc.lib # libstdc++.so.6, libgcc_s.so.1
            zlib # libz.so.1
            zstd # libzstd.so.1
            libGL # libGL.so.1 (opencv)
            glib # libgthread-2.0.so.0 (opencv)
          ];
        in
        {
          default = pkgs.mkShell {
            packages =
              (with pkgs; [
                nodejs_22 # dashboard: next, npm, npx (shadcn)
                sqlite # inspect state / audit db
                uv
                ruff
                basedpyright
                cloudflared # public https URL for the local backend
                just # task runner: `just --list`
              ])
              ++ [ python ]
              ++ pythonRuntimeLibs;

            # Python deps live in gateway/pyproject.toml + uv.lock,
            # JS deps in dashboard/package.json. Nothing global.
            shellHook = ''
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath pythonRuntimeLibs}:''${LD_LIBRARY_PATH:-}"

              # Use the Nix interpreter; never let uv download its own.
              export UV_PYTHON_DOWNLOADS=never
              export UV_PYTHON_PREFERENCE=only-system
              export UV_PYTHON="${python}/bin/python3"

              root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
              (cd "$root/gateway" && uv sync -q)
              [ -d "$root/dashboard/node_modules" ] || (cd "$root/dashboard" && npm install --silent)

              # backend venv first on PATH: python, fastapi, ruff see the deps
              export VIRTUAL_ENV="$root/gateway/.venv"
              export PATH="$VIRTUAL_ENV/bin:$PATH"
            '';
          };
        }
      );
    };
}
