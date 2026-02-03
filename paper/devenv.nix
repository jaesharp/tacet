{ pkgs, lib, ... }:

# devenv.nix for USENIX Security 2026 paper compilation
# Usage: cd paper && devenv shell
# Then: make paper (or latexmk -pdf paper.tex)

{
  packages = [
    pkgs.texliveFull  # Full TeX Live - includes everything
    pkgs.gnumake      # For Makefile
  ];

  # Environment variables for LaTeX
  env = {
    TEXINPUTS = ".::";
    BSTINPUTS = ".::";
    BIBINPUTS = ".::";
  };

  # Shell hook with helpful commands
  enterShell = ''
    echo ""
    echo "USENIX Security 2026 Paper Environment"
    echo "======================================"
    echo ""
    echo "Build commands:"
    echo "  make paper      - Build PDF (pdflatex + bibtex)"
    echo "  make clean      - Remove auxiliary files"
    echo "  make distclean  - Remove all generated files"
    echo "  latexmk -pdf paper.tex  - Alternative build with latexmk"
    echo ""
  '';
}
