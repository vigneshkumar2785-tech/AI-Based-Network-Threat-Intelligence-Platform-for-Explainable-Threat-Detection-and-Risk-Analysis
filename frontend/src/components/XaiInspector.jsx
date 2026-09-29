import React from 'react';
import { Cpu, HelpCircle, ArrowUpRight, ArrowDownRight, Sparkles } from 'lucide-react';

export default function XaiInspector({ xaiData, classification, confidence }) {
  if (!xaiData) return null;

  const shapFeatures = xaiData.shap_features || [];
  const limeFeatures = xaiData.lime_features || [];
  const nlExplanation = xaiData.natural_language_explanation || "Model decision based on feature vector attribution.";

  return (
    <div className="glass-panel rounded-2xl p-6 border border-[#E1E8E5] bg-white space-y-6 shadow-sm">
      <div className="flex items-center justify-between border-b border-[#E1E8E5] pb-4">
        <div>
          <h3 className="text-base font-bold text-[#001E2B] flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-purple-700" />
            Explainable AI (XAI) Model Decision Attribution
          </h3>
          <p className="text-xs text-[#5C6C64] font-mono">
            SHAP TreeExplainer feature attributions & LIME tabular rules explaining XGBoost prediction.
          </p>
        </div>
        <div className="px-3 py-1 bg-purple-50 text-purple-800 border border-purple-200 rounded-lg text-xs font-mono font-bold">
          MODEL: XGBOOST + SHAP
        </div>
      </div>

      {/* Natural Language Explanation Banner */}
      <div className="p-4 bg-[#F9FBF9] rounded-xl border border-[#E1E8E5] text-xs font-mono space-y-1">
        <span className="text-purple-800 font-bold block text-[11px] flex items-center gap-1.5 uppercase">
          <Sparkles className="w-3.5 h-3.5" />
          NATURAL LANGUAGE EXPLANATION
        </span>
        <p className="text-[#001E2B] font-sans text-sm leading-relaxed font-semibold">
          "{nlExplanation}"
        </p>
      </div>

      {/* Grid: SHAP vs LIME */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* SHAP Attributions */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold font-mono text-[#00684A] uppercase tracking-wider flex items-center gap-2">
            <span>SHAP Feature Attributions</span>
            <span className="text-[10px] text-[#5C6C64] font-normal">(Top Drivers)</span>
          </h4>

          <div className="space-y-2">
            {shapFeatures.slice(0, 6).map((feat, idx) => {
              const isPos = feat.direction === 'positive';
              const widthPct = Math.min(Math.max((feat.abs_impact || 0.1) * 100, 15), 100);
              return (
                <div key={idx} className="p-2.5 bg-[#F9FBF9] rounded-lg border border-[#E1E8E5] font-mono text-xs space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-[#001E2B] font-semibold">{feat.feature}</span>
                    <span className={`font-bold flex items-center gap-0.5 ${isPos ? 'text-[#00684A]' : 'text-[#5C6C64]'}`}>
                      {isPos ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                      {feat.shap_value > 0 ? `+${feat.shap_value.toFixed(4)}` : feat.shap_value.toFixed(4)}
                    </span>
                  </div>

                  {/* Impact Bar */}
                  <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${isPos ? 'bg-gradient-to-r from-[#13AA52] to-[#00ED64]' : 'bg-slate-400'}`}
                      style={{ width: `${widthPct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* LIME Rules */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold font-mono text-amber-700 uppercase tracking-wider flex items-center gap-2">
            <span>LIME Decision Rules</span>
            <span className="text-[10px] text-[#5C6C64] font-normal">(Local Approximation)</span>
          </h4>

          <div className="space-y-2">
            {limeFeatures.slice(0, 5).map((rule, idx) => (
              <div key={idx} className="p-2.5 bg-[#F9FBF9] rounded-lg border border-[#E1E8E5] font-mono text-xs space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-amber-800 font-bold">{rule.condition}</span>
                  <span className="text-[#5C6C64] font-bold">w={rule.weight.toFixed(4)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
