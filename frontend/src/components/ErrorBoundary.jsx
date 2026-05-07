import { Component } from "react";

/**
 * ErrorBoundary — catches React render errors inside the Dashboard so an
 * unexpected crash in a result-display component never white-screens the
 * whole app.  The sidebar (ScanForm, ScanProgress, RecentScans) stays fully
 * operational and the user can start a new scan.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, errorMessage: "" };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, errorMessage: error?.message || "Unknown error" };
  }

  componentDidCatch(error, info) {
    console.error("[ErrorBoundary]", error, info?.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, errorMessage: "" });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-full flex-col items-center justify-center gap-4 p-8 text-center">
          <div className="rounded-xl border border-red-700 bg-[#1e293b] p-6 shadow-lg">
            <h2 className="mb-2 text-xl font-semibold text-red-400">
              Dashboard render error
            </h2>
            <p className="mb-4 text-sm text-gray-400">
              Something went wrong displaying this scan result.
              {this.state.errorMessage && (
                <span className="mt-1 block font-mono text-xs text-red-300">
                  {this.state.errorMessage}
                </span>
              )}
            </p>
            <button
              onClick={this.handleReset}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold hover:bg-blue-700"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
