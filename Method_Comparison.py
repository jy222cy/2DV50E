import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# ============================================================================
# Load Real Data from CSV
# ============================================================================
df = pd.read_csv('C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_2/method_comparison.csv', index_col=0)

# Convert to percentages
methods = df.index.tolist()
f1_scores = (df['f1_score'] * 100).tolist()
precision = (df['precision'] * 100).tolist()
recall = (df['recall'] * 100).tolist()
fpr_rates = (df['fpr'] * 100).tolist()
fnr_rates = (df['fnr'] * 100).tolist()

print("="*70)
print("Real Experimental Data Loaded:")
print("="*70)
for i, method in enumerate(methods):
    print(f"{method:30s} | F1={f1_scores[i]:5.2f}% | FPR={fpr_rates[i]:5.2f}%")
print("="*70)

# ============================================================================
# Create Figure with Journal Color Scheme
# ============================================================================
fig, ax = plt.subplots(figsize=(12, 7))

# Journal-standard colors (blue/orange, colorblind-friendly)
color_f1 = '#1f77b4'   # Blue for F1-Score
color_fpr = '#ff7f0e'  # Orange for FPR

# Position settings
x_pos = np.arange(len(methods))
width = 0.35

# Create grouped bar chart
bars1 = ax.bar(x_pos - width/2, f1_scores, width, 
        label='F1-Score (%)', 
        color=color_f1, 
        edgecolor='navy', 
        linewidth=1.5,
        alpha=0.8)

bars2 = ax.bar(x_pos + width/2, fpr_rates, width, 
        label='False Positive Rate (%)', 
        color=color_fpr, 
        edgecolor='darkorange', 
        linewidth=1.5,
        alpha=0.8)

# Add value labels on bars
for i, (bar1, bar2) in enumerate(zip(bars1, bars2)):
    height1 = bar1.get_height()
    height2 = bar2.get_height()
    
    # F1-score labels
    ax.text(bar1.get_x() + bar1.get_width()/2, height1 + 1.5,
        f'{height1:.2f}%', 
        ha='center', va='bottom', 
        fontsize=10, fontweight='bold',
        color='darkblue')

    # FPR labels
    ax.text(bar2.get_x() + bar2.get_width()/2, height2 + 1.5,
        f'{height2:.2f}%', 
        ha='center', va='bottom', 
        fontsize=10, fontweight='bold',
        color='darkorange')

# Highlight the best method (Full Method)
best_idx = f1_scores.index(max(f1_scores))
ax.axvspan(best_idx - 0.4, best_idx + 0.4, alpha=0.15, color='green', zorder=0)
ax.text(best_idx, max(f1_scores) + 8, '★ Best Performance', 
        ha='center', fontsize=11, 
        color='darkgreen', fontweight='bold',
        bbox=dict(boxstyle='round,pad=0.5', facecolor='lightgreen', 
                alpha=0.7, edgecolor='darkgreen', linewidth=1.5))

# Calculate improvements
baseline_f1 = f1_scores[0]  # SQLMap baseline
best_f1 = f1_scores[best_idx]
f1_improvement = best_f1 - baseline_f1
relative_improvement = (f1_improvement / baseline_f1) * 100

# Add F1-score improvement annotation
ax.annotate('', 
        xy=(best_idx - width/2, best_f1), 
        xytext=(0 - width/2, baseline_f1),
        arrowprops=dict(arrowstyle='->', color='blue', lw=2.5, alpha=0.6, 
                        connectionstyle="arc3,rad=.3"))
ax.text(2.5, 78, f'F1 Improvement:\n+{f1_improvement:.2f}%\n({relative_improvement:.1f}% relative)', 
        fontsize=9.5, ha='center', color='darkblue', fontweight='bold',
        bbox=dict(boxstyle='round,pad=0.5', facecolor='lightblue', 
                alpha=0.8, edgecolor='blue', linewidth=1.5))

# Add heuristic contribution (Weighted → Full)
if len(methods) >= 5:
    weighted_idx = 3  # Index of "Weighted Fusion"
    heuristic_contribution = f1_scores[best_idx] - f1_scores[weighted_idx]
    
    ax.annotate('', 
        xy=(best_idx - width/2, best_f1), 
        xytext=(weighted_idx - width/2, f1_scores[weighted_idx]),
        arrowprops=dict(arrowstyle='->', color='purple', lw=2, alpha=0.7))
    ax.text(3.5, 68, f'Heuristic Rules\nContribution:\n+{heuristic_contribution:.2f}%', 
        fontsize=9, ha='center', color='purple', fontweight='bold',
        bbox=dict(boxstyle='round,pad=0.4', facecolor='lavender', 
                alpha=0.8, edgecolor='purple', linewidth=1.5))

# F1-Score trend line
ax.plot(x_pos, f1_scores, 'o--', color='darkblue', 
        linewidth=1.5, markersize=7, alpha=0.4, label='F1 Trend')

# ============================================================================
# Axis Configuration
# ============================================================================
# Shorten method names for X-axis
short_names = []
for m in methods:
    if 'SQLMap' in m:
        short_names.append('SQLMap\nOnly')
    elif 'ZAP' in m:
        short_names.append('ZAP\nOnly')
    elif 'Simple Average' in m:
        short_names.append('Simple\nAverage')
    elif 'Weighted Fusion' in m:
        short_names.append('Weighted\nFusion')
    elif 'Full' in m or 'Heuristics' in m:
        short_names.append('Full Method\n(+Heuristics)')
    else:
        short_names.append(m)

ax.set_xlabel('Detection Method', fontsize=13, fontweight='bold')
ax.set_ylabel('Percentage (%)', fontsize=13, fontweight='bold')
ax.set_title('Detection Method Performance Comparison\n' + 
        'Multi-Source Fusion Effectiveness (n=55 test cases)',
        fontsize=14, fontweight='bold', pad=20)

ax.set_xticks(x_pos)
ax.set_xticklabels(short_names, fontsize=10)

ax.set_ylim(0, 95)
ax.set_yticks(np.arange(0, 100, 10))
ax.tick_params(axis='both', which='major', labelsize=10)

ax.legend(loc='upper left', fontsize=11, framealpha=0.95, 
        edgecolor='black', fancybox=True)

ax.grid(True, alpha=0.3, axis='y', linestyle='--')

# ============================================================================
# Save
# ============================================================================
output_jpg = 'C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_2/method_comparison.jpg'
plt.savefig(output_jpg, dpi=300, bbox_inches='tight', facecolor='white')
print(f"\n✅ Method comparison chart saved:")
print(f"  JPG: {output_jpg}")

plt.close()

# ============================================================================
# Generate Detailed Statistics Table
# ============================================================================
stats_df = pd.DataFrame({
'Method': methods,
'Precision (%)': [f'{p:.2f}' for p in precision],
'Recall (%)': [f'{r:.2f}' for r in recall],
'F1-Score (%)': [f'{f:.2f}' for f in f1_scores],
'FPR (%)': [f'{fpr:.2f}' for fpr in fpr_rates],
'FNR (%)': [f'{fnr:.2f}' for fnr in fnr_rates]
})

stats_file = 'C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_2/method_comparison_statistics.csv'
stats_df.to_csv(stats_file, index=False)
print(f"✅ Detailed statistics saved: {stats_file}")

print("\n" + "="*70)
print("Performance Summary:")
print("="*70)
print(stats_df.to_string(index=False))
print("="*70)