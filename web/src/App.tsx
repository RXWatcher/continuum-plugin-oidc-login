import { Route, Routes, Navigate } from "react-router";
import Layout from "./components/Layout";
import Admin from "./pages/Admin";
import { Toaster } from "./components/ui/sonner";

export default function App() {
  return (
    <>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Admin />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
      <Toaster />
    </>
  );
}
