import { useEffect, useState } from "react";
import { Alert, Button, Container, Table } from "react-bootstrap";
import api from "../../services/api.service";

export default function Returns() {
  const [files, setFiles] = useState([]);
  const [integration, setIntegration] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    async function load() {
      try {
        const integrations = await api.listintegration();
        const destination = integrations.find(i => i.Provider === "localfs" && i.PreserveVersions);
        let returned = [];
        if (destination) {
          const folder = await api.exploreIntegration(destination.ID);
          returned = folder.files.filter(f => f.fileExtension === "pdf")
            .sort((a, b) => new Date(b.dateChanged) - new Date(a.dateChanged));
        }
        if (active) { setIntegration(destination); setFiles(returned); }
      } catch (_) {
        if (active) setError("Could not load returned PDFs. Try Refresh.");
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => { active = false; };
  }, [refresh]);

  return <Container className="py-4" style={{ height: "100%", overflow: "auto" }}>
    <div className="d-flex align-items-center justify-content-between mb-3">
      <h2>Returns</h2>
      <Button variant="outline-secondary" disabled={loading} onClick={() => setRefresh(r => r + 1)}>Refresh</Button>
    </div>
    <p>On your tablet, long-press a document, choose Export, then {integration?.Name || "Laptop Returns"}. Your PDF includes the annotations; earlier exports stay available.</p>
    {error && <Alert variant="danger">{error}</Alert>}
    {loading ? <p>Loading returned PDFs…</p> : !error && !integration ?
      <Alert variant="info">Your return destination has not been configured yet.</Alert> : !error && !files.length ?
      <p>No returned PDFs yet. Export one from your tablet, then Refresh.</p> : !error && <>
        <p className="text-muted">Newest first. Your original documents are kept separately.</p>
        <Table responsive>
          <thead><tr><th>PDF</th><th>Returned</th><th></th></tr></thead>
          <tbody>{files.map(file => <tr key={file.id}>
            <td>{file.name}.pdf</td>
            <td>{new Date(file.dateChanged).toLocaleString()}</td>
            <td className="text-nowrap">
              <Button as="a" variant="outline-primary" size="sm" className="me-2" href={api.integrationDownload(integration.ID, file.id)} target="_blank" rel="noopener noreferrer">Open</Button>
              <Button as="a" variant="primary" size="sm" href={api.integrationDownload(integration.ID, file.id, true)}>Download</Button>
            </td>
          </tr>)}</tbody>
        </Table>
      </>}
  </Container>;
}
