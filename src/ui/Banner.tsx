// Two things the app refuses to keep quiet about: an operation that failed,
// and checks that could not measure. A check that could not run is not a check
// that passed, so it never hides inside the "all clear" count.
import { issues } from "../cell/issues.ts";

export function Banner() {
  const failed = issues.failed;
  return (
    <>
      {issues.error && (
        <div className="banner" t="error" role="alert">
          <span>{issues.error}</span>
          <div className="spacer" />
          <button
            type="button"
            t="dismiss"
            className="btn small"
            onClick={() => issues.dismissError()}
          >
            Dismiss
          </button>
        </div>
      )}
      {failed.length > 0 && (
        <div className="banner info" t="unmeasured" role="status">
          {failed.length} check{failed.length === 1 ? "" : "s"}{" "}
          could not measure on this machine: {failed.join(", ")}
        </div>
      )}
    </>
  );
}
