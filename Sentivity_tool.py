import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# ==============================================================================
# Configuration
# ==============================================================================
INPUT_CSV = Path("C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_5/sensitivity_tool_weight_sqlmap.csv")
OUTPUT_DIR = Path("C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_5/")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Colors matching Summary.png style
COLOR_LINE = '#9370DB'      # Purple line
COLOR_FILL = '#E6D5FF'      # Light purple background
COLOR_MAX_LINE = '#FF1493'  # Deep pink for max line

# ==============================================================================
# Load and Process Data
# ==============================================================================
print("="*70)
print("PARAMETER SENSITIVITY ANALYSIS - SUMMARY STYLE")
print("="*70)

df = pd.read_csv(INPUT_CSV)

# Extract weights and F1 scores
weights = []
f1_scores = []

for idx, row in df.iterrows():
    weight_str = row.iloc[0]  # e.g., "tool_weight_sqlmap=0.4"
    weight = float(weight_str.split('=')[1])
    f1 = row['f1_score']
    
    weights.append(weight)
    f1_scores.append(f1)

# Calculate statistics
f1_mean = np.mean(f1_scores)
f1_std = np.std(f1_scores)
f1_max = np.max(f1_scores)
f1_min = np.min(f1_scores)
cv = (f1_std / f1_mean) * 100  # Coefficient of Variation

# ==============================================================================
# Create Line Plot
# ==============================================================================
fig, ax = plt.subplots(figsize=(8, 6))

# Fill background with light purple
ax.fill_between(weights, 0.80, 0.90, color=COLOR_FILL, alpha=0.3, zorder=1)

# Plot main line with markers
ax.plot(weights, f1_scores, 'o-', 
        color=COLOR_LINE, linewidth=3, markersize=10,
        markeredgecolor='darkviolet', markeredgewidth=2,
        label='F1-Score', zorder=3)

# Add horizontal dashed line for max F1
ax.axhline(y=f1_max, color=COLOR_MAX_LINE, linestyle='--', 
           linewidth=2, alpha=0.7, zorder=2,
           label=f'Max F1={f1_max:.4f}')

# Add value labels on key points
for i, (w, f1) in enumerate(zip(weights, f1_scores)):
    # Only label first, max, and last points to avoid clutter
    if i == 0 or f1 == f1_max or i == len(weights) - 1:
        ax.text(w, f1 + 0.002, f'{f1:.4f}',
                ha='center', va='bottom', fontsize=9, 
                fontweight='bold', color='darkviolet')

# Styling - matching Summary.png
ax.set_xlabel('SQLMap Weight', fontsize=13, fontweight='bold')
ax.set_ylabel('F1-Score', fontsize=13, fontweight='bold')
ax.set_title(f'RQ4: Parameter Robustness\nCV={cv:.2f}% (Highly Robust)',
             fontsize=14, fontweight='bold', pad=15)

# Set axis limits
ax.set_xlim(0.38, 0.72)
ax.set_ylim(0.80, 0.90)

# Grid styling
ax.grid(axis='both', alpha=0.3, linestyle='--', linewidth=0.8, zorder=0)
ax.set_axisbelow(True)

# Spine styling
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_linewidth(1.5)
ax.spines['bottom'].set_linewidth(1.5)

# Legend
ax.legend(loc='lower left', fontsize=10, framealpha=0.95,
          edgecolor='black', fancybox=True)

# Set white background
fig.patch.set_facecolor('white')
ax.set_facecolor('white')

plt.tight_layout()

# Save outputs
jpg_file = OUTPUT_DIR / 'sensitivity_tool.jpg'
plt.savefig(jpg_file, dpi=300, bbox_inches='tight')

print(f"\n✅ Saved JPG: {jpg_file}")
