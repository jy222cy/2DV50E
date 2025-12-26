import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# ============================================================================
# Load Data
# ============================================================================
df = pd.read_csv('C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_1/individual_confidence_scores.csv')

# Separate by ground truth (keep full DataFrame for TCID access)
true_positives_df = df[df['Ground Truth'] == 'True Vulnerability']
true_negatives_df = df[df['Ground Truth'] == 'Secure Implementation']

true_positives = true_positives_df['Confidence Score'].values
true_negatives = true_negatives_df['Confidence Score'].values

# ============================================================================
# Identify Outliers
# ============================================================================
# False Positives: Secure Implementations with confidence > 0.50
false_positives = true_negatives_df[true_negatives_df['Confidence Score'] > 0.50]

# False Negatives: True Vulnerabilities with confidence < 0.50
false_negatives = true_positives_df[true_positives_df['Confidence Score'] < 0.50]

# ============================================================================
# Calculate Statistics
# ============================================================================
tp_mean = np.mean(true_positives)
tn_mean = np.mean(true_negatives)
tp_median = np.median(true_positives)
tn_median = np.median(true_negatives)

print(f"\n{'='*70}")
print("DISTRIBUTION STATISTICS")
print("="*70)

# ============================================================================
# Create Box Plot with Journal Color Scheme
# ============================================================================
fig, ax = plt.subplots(figsize=(12, 7))

# Journal-standard colors (Nature/Science compatible, colorblind-friendly)
color_tp = '#1f77b4'  # Blue - for True Positives (vulnerabilities)
color_tn = '#ff7f0e'  # Orange - for True Negatives (secure)

# Create box plot
bp = ax.boxplot(
    [true_positives, true_negatives],
    positions=[1, 2],
    widths=0.6,
    patch_artist=True,
    showmeans=True,
    meanprops=dict(marker='D', markerfacecolor='white', markeredgecolor='black', 
                markersize=8, markeredgewidth=1.5, label='Mean'),
    medianprops=dict(color='black', linewidth=2),
    boxprops=dict(linewidth=1.5),
    whiskerprops=dict(linewidth=1.5),
    capprops=dict(linewidth=1.5),
    flierprops=dict(marker='o', markerfacecolor='gray', markersize=6, 
                    linestyle='none', markeredgecolor='gray', alpha=0.5)  # Made transparent
)

# Color the boxes
bp['boxes'][0].set_facecolor(color_tp)
bp['boxes'][0].set_alpha(0.7)
bp['boxes'][1].set_facecolor(color_tn)
bp['boxes'][1].set_alpha(0.7)

# Add classification threshold line
ax.axhline(y=0.50, color='gray', linestyle='--', linewidth=2, 
        label='Classification Threshold (0.50)', alpha=0.8, zorder=1)

# Left side (True Positives): Move UP to clear the blue box
ax.text(1, tp_mean + 0.12, f'μ={tp_mean:.3f}', 
        ha='center', va='bottom', fontsize=11, fontweight='bold',
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', 
                edgecolor='darkblue', alpha=0.9))

# Right side (True Negatives): Move DOWN to clear the orange box
ax.text(2, tn_mean - 0.08, f'μ={tn_mean:.3f}', 
        ha='center', va='top', fontsize=11, fontweight='bold',
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', 
                edgecolor='darkorange', alpha=0.9))

# ============================================================================
# Annotate FALSE POSITIVES (Red markers with TCID labels)
# ============================================================================
fp_sorted = false_positives.sort_values('Confidence Score', ascending=False)

for i, (idx, row) in enumerate(fp_sorted.iterrows()):
    tcid = row['Test_ID']
    conf = row['Confidence Score']
    
    # Red markers for false positives
    ax.plot(2, conf, 'o', color='red', markersize=10, 
        markeredgecolor='darkred', markeredgewidth=2, 
        zorder=10, alpha=0.9, label='False Positive' if i == 0 else '')
    
    # Alternate left-right: even index=left (ha='right'), odd index=right (ha='left')
    if i % 2 == 0:  # TC049, TC048, TC050 - LEFT side
        label_x = 1.92
        label_ha = 'right'
    else:  # TC046, TC047 - RIGHT side
        label_x = 2.08
        label_ha = 'left'
    
    # Add TCID label
    ax.text(label_x, conf, f'{tcid}', 
        fontsize=9, color='darkred', 
        weight='bold', ha=label_ha, va='center',
        bbox=dict(boxstyle='round,pad=0.3', 
                facecolor='white', 
                edgecolor='red', 
                alpha=0.9))

# ============================================================================
# Annotate FALSE NEGATIVES (Dark blue markers with TCID labels)
# ============================================================================
fn_sorted = false_negatives.sort_values('Confidence Score', ascending=False)

for i, (idx, row) in enumerate(fn_sorted.iterrows()):
    tcid = row['Test_ID']
    conf = row['Confidence Score']
    
    # Dark blue markers for false negatives
    ax.plot(1, conf, 'o', color='darkblue', markersize=10, 
        markeredgecolor='navy', markeredgewidth=2, 
        zorder=10, alpha=0.9, label='False Negative' if i == 0 else '')
    
    # Alternate left-right: even index=left (ha='right'), odd index=right (ha='left')
    if i % 2 == 0:  # TC008, TC015, TC030, TC031 - LEFT side
        label_x = 0.92
        label_ha = 'right'
    else:  # TC011, TC023, TC032 - RIGHT side
        label_x = 1.08
        label_ha = 'left'
    
    if tcid == 'TC030':
        label_y = conf + 0.04  # Move up by 0.04 units
    else:
        label_y = conf  # Keep original position
    
    # Add TCID label
    ax.text(label_x, label_y, f'{tcid}', 
        fontsize=9, color='navy', 
        weight='bold', ha=label_ha, va='center',
        bbox=dict(boxstyle='round,pad=0.3', 
                facecolor='white', 
                edgecolor='darkblue', 
                alpha=0.9))

# ============================================================================
# Formatting
# ============================================================================
ax.set_ylabel('Confidence Score', fontsize=13, fontweight='bold')
ax.set_xlabel('Ground Truth Category', fontsize=13, fontweight='bold')
ax.set_title('Confidence Score Distribution by Ground Truth Label\n(with Outlier Identification)', 
            fontsize=14, fontweight='bold', pad=20)

# X-axis labels
ax.set_xticks([1, 2])
ax.set_xticklabels([
    f'True Vulnerabilities\n(n={len(true_positives)})', 
    f'Secure Implementations\n(n={len(true_negatives)})'
], fontsize=11)

# Y-axis
ax.set_ylim(-0.05, 1.05)
ax.set_yticks(np.arange(0, 1.1, 0.1))
ax.tick_params(axis='both', which='major', labelsize=11)
ax.grid(axis='y', alpha=0.3, linestyle=':', linewidth=0.8)

# ============================================================================
# Legend (moved to lower left to avoid overlapping with blue box)
# ============================================================================
legend_elements = [
    plt.Line2D([0], [0], color=color_tp, lw=8, alpha=0.7, label='True Vulnerabilities'),
    plt.Line2D([0], [0], color=color_tn, lw=8, alpha=0.7, label='Secure Implementations'),
    plt.Line2D([0], [0], color='gray', linestyle='--', lw=2, label='Threshold (0.50)'),
    plt.Line2D([0], [0], marker='D', color='w', markerfacecolor='white', 
            markeredgecolor='black', markersize=8, markeredgewidth=1.5, 
            linestyle='None', label='Mean'),
    plt.Line2D([0], [0], marker='o', color='red', linestyle='None',
            markersize=9, markeredgecolor='darkred', markeredgewidth=2,
            label=f'False Positive (n={len(false_positives)})', alpha=0.9),
    plt.Line2D([0], [0], marker='o', color='darkblue', linestyle='None',
            markersize=9, markeredgecolor='navy', markeredgewidth=2,
            label=f'False Negative (n={len(false_negatives)})', alpha=0.9)
]
ax.legend(handles=legend_elements, loc='lower left', fontsize=10, framealpha=0.95)

# Tight layout
plt.tight_layout()

# ============================================================================
# Save
# ============================================================================
output_path = 'C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_1/confidence_boxplot.jpg'
plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
print(f"\n✅ Box plot saved: {output_path}")

plt.close()
