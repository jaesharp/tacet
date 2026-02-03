# Makefile for USENIX Security 2026 Paper
# Usage: make paper

.PHONY: all paper clean distclean view wordcount pagecount help watch

# Default target
all: paper

# Main PDF target
paper: paper.pdf

# Build PDF with pdflatex and bibtex (traditional method)
paper.pdf: paper.tex paper.bib usenix.sty
	@echo "Building paper.pdf..."
	@echo "  Pass 1: pdflatex"
	@pdflatex -interaction=nonstopmode -halt-on-error paper.tex > /dev/null 2>&1 || \
		(pdflatex -interaction=nonstopmode paper.tex && false)
	@echo "  Pass 2: bibtex"
	@bibtex paper > /dev/null 2>&1 || true
	@echo "  Pass 3: pdflatex"
	@pdflatex -interaction=nonstopmode -halt-on-error paper.tex > /dev/null 2>&1 || true
	@echo "  Pass 4: pdflatex"
	@pdflatex -interaction=nonstopmode -halt-on-error paper.tex > /dev/null 2>&1 || true
	@echo "Done: paper.pdf"
	@echo ""
	@$(MAKE) --no-print-directory pagecount

# Alternative: use latexmk for smarter builds
latexmk: paper.tex paper.bib usenix.sty
	@echo "Building with latexmk..."
	latexmk -pdf -pdflatex="pdflatex -interaction=nonstopmode" paper.tex
	@$(MAKE) --no-print-directory pagecount

# Watch mode with latexmk (auto-rebuild on changes)
watch: paper.tex paper.bib usenix.sty
	@echo "Starting watch mode (Ctrl+C to stop)..."
	latexmk -pdf -pvc -pdflatex="pdflatex -interaction=nonstopmode" paper.tex

# Clean auxiliary files but keep PDF
clean:
	@echo "Cleaning auxiliary files..."
	@rm -f paper.aux paper.bbl paper.blg paper.log paper.out paper.toc
	@rm -f paper.fdb_latexmk paper.fls paper.synctex.gz
	@rm -f *.aux *.bbl *.blg *.log *.out *.toc *.fdb_latexmk *.fls *.synctex.gz
	@rm -f *~ \#*

# Complete cleanup including PDF
distclean: clean
	@echo "Removing PDF..."
	@rm -f paper.pdf

# View the PDF (macOS)
view: paper.pdf
	@open paper.pdf 2>/dev/null || \
		xdg-open paper.pdf 2>/dev/null || \
		evince paper.pdf 2>/dev/null || \
		echo "Could not open PDF viewer"

# Approximate word count (body only, excluding comments and markup)
wordcount: paper.tex
	@echo "Approximate word count (body text):"
	@if command -v detex > /dev/null 2>&1; then \
		detex paper.tex 2>/dev/null | wc -w | xargs echo "  "; \
	else \
		echo "  detex not available, using simple count:"; \
		grep -v '^%' paper.tex | wc -w | xargs echo "  "; \
	fi

# Page count (requires PDF to exist)
pagecount: paper.pdf
	@if command -v pdfinfo > /dev/null 2>&1; then \
		pages=$$(pdfinfo paper.pdf 2>/dev/null | grep Pages | awk '{print $$2}'); \
		echo "Page count: $$pages pages (13 max for body)"; \
	elif command -v pdftk > /dev/null 2>&1; then \
		pages=$$(pdftk paper.pdf dump_data 2>/dev/null | grep NumberOfPages | awk '{print $$2}'); \
		echo "Page count: $$pages pages (13 max for body)"; \
	else \
		echo "Page count: install pdfinfo or pdftk to check"; \
	fi

# Show help
help:
	@echo "USENIX Security 2026 Paper Makefile"
	@echo "===================================="
	@echo ""
	@echo "Targets:"
	@echo "  make paper      - Build PDF with pdflatex (default)"
	@echo "  make latexmk    - Build PDF with latexmk (smarter rebuilds)"
	@echo "  make watch      - Auto-rebuild on file changes"
	@echo "  make clean      - Remove auxiliary files"
	@echo "  make distclean  - Remove all generated files including PDF"
	@echo "  make view       - Open PDF in default viewer"
	@echo "  make wordcount  - Estimate word count"
	@echo "  make pagecount  - Show page count"
	@echo "  make help       - Show this message"
	@echo ""
	@echo "USENIX Requirements:"
	@echo "  - Body: max 13 pages (two-column, 10pt)"
	@echo "  - Required appendices: Ethical Considerations, Open Science"
	@echo "  - Final: max 20 total pages (body + appendices + refs)"
