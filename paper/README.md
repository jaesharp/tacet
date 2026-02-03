# Tacet: Reliable Timing Side-Channel Detection via Bayesian Inference

## USENIX Security 2026 Paper Submission

This directory contains the LaTeX setup for the Tacet paper submission to USENIX Security 2026.

### Project Structure

```
paper/
├── paper.tex              - Main LaTeX document with complete section structure
├── paper.bib              - Bibliography file (placeholder)
├── usenix2019_v3.cls      - USENIX Security document class
├── Makefile               - Build automation
├── paper.pdf              - Generated PDF (created via make)
└── README.md              - This file
```

### Building the Paper

```bash
# Build the PDF
make
# or
make paper

# Clean auxiliary files (keeps PDF)
make clean

# Remove all generated files including PDF
make distclean

# View the PDF
make view

# Estimate word count
make wordcount
```

### Paper Structure

The main document (`paper.tex`) includes the following sections:

1. **Abstract**
2. **Introduction** (~1.25 pages)
3. **Background and Related Work** (~1.25 pages)
4. **Tacet's Approach** (~3.5 pages)
   - 4.1: Calibrated Verdicts
   - 4.2: Quantile-Based Test Statistic
   - 4.3: Probabilistic Inference
   - 4.4: Quality Gates
   - 4.5: Worked Example
5. **Implementation** (~0.75 pages)
6. **Evaluation** (~3.5 pages)
   - 6.1: Methodology
   - 6.2: Results
   - 6.3: Crypto Library Validation
7. **Discussion and Limitations** (~0.75 pages)
8. **Conclusion** (~0.5 pages)
9. **Appendices**
   - Ethical Considerations
   - Open Science
   - Statistical Methodology (optional)

### Notes

- Current placeholders use `\lipsum` for filler text and `TBD` for section content
- Replace these with actual content as the paper develops
- The document uses two-column layout as required by USENIX
- Bibliography entries should be added to `paper.bib`
- Compilation requires pdflatex and bibtex

### Environment Setup

LaTeX dependencies have been added to `/sessions/epic-quirky-rubin/mnt/tacet/devenv.nix`:
- `texlive.combined.scheme-full`
- `bibtex-tray`
- `latexmk`

These can be installed/enabled via the devenv configuration.
