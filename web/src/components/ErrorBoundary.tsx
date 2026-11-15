import React from "react";
export default class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (this.state.error) return (
      <div className="card m-4 border-rose-700 text-sm">
        <div className="mb-1 font-semibold text-rose-400">画面の描画でエラーが発生しました</div>
        <pre className="whitespace-pre-wrap text-xs text-slate-300">{String(this.state.error?.stack ?? this.state.error)}</pre>
        <button className="btn-secondary mt-2" onClick={() => this.setState({ error: null })}>再試行</button>
      </div>
    );
    return this.props.children;
  }
}
