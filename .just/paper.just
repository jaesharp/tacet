# Paper (LaTeX) commands
# USENIX Security 2026 paper compilation
#
# NOTE: Requires LaTeX tools (pdflatex, bibtex, latexmk) from devenv.
# These are available when direnv is loaded (automatic in your terminal).

paper_dir := justfile_directory() + "/paper"

# Build the PDF (default)
[group('paper')]
build:
    @echo "Building paper.pdf..."
    cd {{paper_dir}} && pdflatex -interaction=nonstopmode -halt-on-error paper.tex > /dev/null 2>&1 || pdflatex -interaction=nonstopmode paper.tex
    @echo "  Running bibtex..."
    -cd {{paper_dir}} && bibtex paper > /dev/null 2>&1
    @echo "  Pass 2..."
    -cd {{paper_dir}} && pdflatex -interaction=nonstopmode -halt-on-error paper.tex > /dev/null 2>&1
    @echo "  Pass 3..."
    -cd {{paper_dir}} && pdflatex -interaction=nonstopmode -halt-on-error paper.tex > /dev/null 2>&1
    @echo "Done: paper/paper.pdf"
    @just paper::pagecount

# Build with latexmk (smarter incremental builds)
[group('paper')]
latexmk:
    cd {{paper_dir}} && latexmk -pdf -pdflatex="pdflatex -interaction=nonstopmode" paper.tex
    @just paper::pagecount

# Watch mode: auto-rebuild on file changes
[group('paper')]
watch:
    @echo "Starting watch mode (Ctrl+C to stop)..."
    cd {{paper_dir}} && latexmk -pdf -pvc -pdflatex="pdflatex -interaction=nonstopmode" paper.tex

# Clean auxiliary files (keep PDF)
[group('paper')]
clean:
    @echo "Cleaning auxiliary files..."
    cd {{paper_dir}} && rm -f paper.aux paper.bbl paper.blg paper.log paper.out paper.toc
    cd {{paper_dir}} && rm -f paper.fdb_latexmk paper.fls paper.synctex.gz
    cd {{paper_dir}} && rm -f *.aux *.bbl *.blg *.log *.out *.toc *.fdb_latexmk *.fls *.synctex.gz
    cd {{paper_dir}} && rm -f *~ \#*

# Remove all generated files including PDF
[group('paper')]
distclean: clean
    @echo "Removing PDF..."
    cd {{paper_dir}} && rm -f paper.pdf

# Open the PDF in default viewer
[group('paper')]
view:
    @if [ -f "{{paper_dir}}/paper.pdf" ]; then \
        open "{{paper_dir}}/paper.pdf" 2>/dev/null || \
        xdg-open "{{paper_dir}}/paper.pdf" 2>/dev/null || \
        echo "Could not open PDF viewer"; \
    else \
        echo "paper.pdf not found. Run 'just paper build' first."; \
    fi

# Build and open PDF
[group('paper')]
open: build view

# Approximate word count (body text only)
[group('paper')]
wordcount:
    @echo "Approximate word count (body text):"
    @if command -v detex > /dev/null 2>&1; then \
        detex "{{paper_dir}}/paper.tex" 2>/dev/null | wc -w | xargs echo "  "; \
    else \
        echo "  (detex not available, using simple count)"; \
        grep -v '^%' "{{paper_dir}}/paper.tex" | wc -w | xargs echo "  "; \
    fi

# Show page count (13 max for body)
[group('paper')]
pagecount:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f "{{paper_dir}}/paper.pdf" ]; then
        if command -v pdfinfo > /dev/null 2>&1; then
            pages=$(pdfinfo "{{paper_dir}}/paper.pdf" 2>/dev/null | grep Pages | awk '{print $2}')
            echo "Page count: $pages pages (13 max for body)"
        elif command -v pdftk > /dev/null 2>&1; then
            pages=$(pdftk "{{paper_dir}}/paper.pdf" dump_data 2>/dev/null | grep NumberOfPages | awk '{print $2}')
            echo "Page count: $pages pages (13 max for body)"
        else
            echo "Page count: install pdfinfo or pdftk to check"
        fi
    else
        echo "Page count: paper.pdf not found"
    fi

# Check for common LaTeX issues
[group('paper')]
check:
    @echo "Checking for common issues..."
    @echo ""
    @echo "Overfull/underfull boxes:"
    @grep -n "Overfull\|Underfull" "{{paper_dir}}/paper.log" 2>/dev/null | head -20 || echo "  (none found or no log file)"
    @echo ""
    @echo "Undefined references:"
    @grep -n "undefined" "{{paper_dir}}/paper.log" 2>/dev/null | head -10 || echo "  (none found)"
    @echo ""
    @echo "Missing citations:"
    @grep -n "Citation.*undefined" "{{paper_dir}}/paper.log" 2>/dev/null | head -10 || echo "  (none found)"

# Run spell check with aspell (interactive)
[group('paper')]
spellcheck:
    @if command -v aspell > /dev/null 2>&1; then \
        aspell --mode=tex --lang=en check "{{paper_dir}}/paper.tex"; \
    else \
        echo "aspell not installed. Install with: brew install aspell"; \
    fi

# Show bibliography entries
[group('paper')]
refs:
    @echo "Bibliography entries in paper.bib:"
    @grep -E "^@" "{{paper_dir}}/paper.bib" | sort

# Count citations used in the paper
[group('paper')]
cite-count:
    @echo "Citations in paper.tex:"
    @grep -oE '\\cite\{[^}]+\}' "{{paper_dir}}/paper.tex" | sort | uniq -c | sort -rn

# Show USENIX requirements
[group('paper')]
requirements:
    @echo "USENIX Security 2026 Requirements"
    @echo "=================================="
    @echo ""
    @echo "Format:"
    @echo "  - Two-column, 10pt font"
    @echo "  - Use usenix.sty (provided)"
    @echo ""
    @echo "Length limits:"
    @echo "  - Body: max 13 pages"
    @echo "  - References: unlimited (but reasonable)"
    @echo "  - Final: max 20 total pages (body + appendices + refs)"
    @echo ""
    @echo "Required appendices:"
    @echo "  - Ethical Considerations"
    @echo "  - Open Science Policy"
    @echo ""
    @echo "Current status:"
    @just paper::pagecount
    @just paper::wordcount
