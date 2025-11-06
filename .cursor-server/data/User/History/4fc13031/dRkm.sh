#!/bin/bash
##############################################################################
# Compile IEEE Paper
# Requires: texlive-full or equivalent LaTeX distribution
##############################################################################

PAPER_DIR="/home/jarvis/thesis"
cd "$PAPER_DIR"

echo "======================================"
echo "Compiling IEEE Research Paper"
echo "======================================"

# Check if LaTeX is installed
if ! command -v pdflatex &> /dev/null; then
    echo "ERROR: pdflatex not found!"
    echo "Install with: sudo apt-get install texlive-full"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -f paper.aux paper.bbl paper.blg paper.log paper.out paper.pdf

# First pass
echo "Running pdflatex (pass 1/3)..."
pdflatex -interaction=nonstopmode paper.tex > /dev/null

# BibTeX
if [ -f references.bib ]; then
    echo "Running bibtex..."
    bibtex paper > /dev/null
fi

# Second pass
echo "Running pdflatex (pass 2/3)..."
pdflatex -interaction=nonstopmode paper.tex > /dev/null

# Third pass
echo "Running pdflatex (pass 3/3)..."
pdflatex -interaction=nonstopmode paper.tex

# Check if successful
if [ -f paper.pdf ]; then
    echo "======================================"
    echo "✓ Paper compiled successfully!"
    echo "Output: $PAPER_DIR/paper.pdf"
    echo "Pages: $(pdfinfo paper.pdf 2>/dev/null | grep Pages | awk '{print $2}')"
    echo "Size: $(du -h paper.pdf | awk '{print $1}')"
    echo "======================================"
    
    # Open PDF (optional)
    # xdg-open paper.pdf &
else
    echo "======================================"
    echo "✗ Compilation failed!"
    echo "Check paper.log for errors"
    echo "======================================"
    exit 1
fi

# Clean auxiliary files (optional)
# rm -f paper.aux paper.bbl paper.blg paper.log paper.out

