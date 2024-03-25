import React, { useEffect, useState } from 'react';
import { Modal, Button } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);

  const fetchAlerts = () => {
    const queryParam = searchQuery ? `?search=${searchQuery}` : ''; 
    fetch(`http://95.217.188.129:5000/alerts${queryParam}`)
      .then(response => response.json())
      .then(data => setAlerts(data.alerts))
      .catch(error => console.error('Error fetching data: ', error));
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 1000);
    return () => clearInterval(interval);
  }, [searchQuery]);

  const runScript = () => {
    fetch('http://95.217.188.129:5000/run-script')
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then(data => console.log('Script run successfully:', data))
      .catch(error => console.error('Error running script: ', error));
  };

  const handleCloseModal = () => setSelectedAlert(null);

  return (
    <div className="container mt-5">
      <h2 className="mb-4">Latest Alerts</h2>
      <div className="input-group mb-3">
        <input 
          type="text" 
          className="form-control" 
          placeholder="Search alerts..." 
          value={searchQuery} 
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <div className="input-group-append">
          <button className="btn btn-outline-secondary" onClick={fetchAlerts}>Search</button>
          <button className="btn btn-danger ml-2" onClick={runScript}>Run Script</button>
        </div>
      </div>

      <div className="list-group">
        {alerts.map((alert, index) => (
          <div 
            key={index} 
            className="list-group-item flex-column align-items-start" 
            style={{ cursor: 'pointer' }}
            onClick={() => setSelectedAlert(alert)}
          >
            <div className="d-flex w-100 justify-content-between">
              <h5 className="mb-1">
                <span dangerouslySetInnerHTML={{ __html: alert.title }}></span>
              </h5>
              <small>{new Date(alert.pub_date).toLocaleString()}</small>
            </div>
          </div>
        ))}
      </div>

      {selectedAlert && (
        <Modal show={selectedAlert !== null} onHide={handleCloseModal} size="lg">
          <Modal.Header closeButton>
            <Modal.Title>
              <span dangerouslySetInnerHTML={{ __html: selectedAlert.title }}></span>  
            </Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <p dangerouslySetInnerHTML={{ __html: selectedAlert.description }}></p>
            {selectedAlert.media_urls && selectedAlert.media_urls.map((url, index) => (
              <img key={index} src={url} alt="Media" className="img-fluid mt-2" style={{ maxHeight: '200px' }} />
            ))}
            <br /><br />
            <a className="btn btn-primary mt-2" href={selectedAlert.link} role="button">Article URL</a>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={handleCloseModal}>
              Close
            </Button>
          </Modal.Footer>
        </Modal>
      )}
    </div>
  );
}

export default App;
