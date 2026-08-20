// Root UI — layout only. Every component below reads the one cell directly.
import { Header } from "./ui/Header.tsx";
import { Banner } from "./ui/Banner.tsx";
import { RootPlan } from "./ui/RootPlan.tsx";
import { IssueTable } from "./ui/IssueTable.tsx";
import { FixLog } from "./ui/FixLog.tsx";

export default function App() {
  return (
    <main className="app">
      <Header />
      <Banner />
      <RootPlan />
      <IssueTable />
      <FixLog />
    </main>
  );
}
