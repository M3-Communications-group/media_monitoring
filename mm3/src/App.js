import React, { useEffect, useState } from 'react';
import { Modal, Button } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
import { Dropdown } from 'react-bootstrap';
import './App.css';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [keywords] = useState(['urgent', 'breaking']);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const highlightKeywords = (text, keywords) => {
    if (!keywords.length) {
      return text;
    }
    const regex = new RegExp(`(${keywords.join('|')})`, 'gi');
    return text.replace(regex, (match) => `<span class="highlight">${match}</span>`);
  };

  const [isNewSignal, setIsNewSignal] = useState(false);
  
  const fetchAlerts = () => {
    const queryParam = `?page=${currentPage}&search=${searchQuery}`;
    fetch(`http://95.217.188.129:5000/alerts${queryParam}`)
      .then(response => response.json())
      .then(data => {
        if (data.alerts.length > 0 && alerts.length > 0 && data.alerts[0].id !== alerts[0].id) {
          setIsNewSignal(true);
          setTimeout(() => setIsNewSignal(false), 1000);
        }
        setAlerts(data.alerts.map(alert => ({
          ...alert,
          title: highlightKeywords(alert.title, keywords),
          description: highlightKeywords(alert.description, keywords)
        })));
        setTotalPages(data.total_pages);
      })
      .catch(error => console.error('Error fetching data: ', error));
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 1000);
    return () => clearInterval(interval);
  }, [searchQuery, currentPage]);

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

  useEffect(() => {
    const interval = setInterval(runScript, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

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

      <div className={`list-group ${isNewSignal ? 'pulse' : ''}`}>
        {alerts.map((alert, index) => (
          <div 
            key={index} 
            className="list-group-item flex-column align-items-start" 
            style={{ cursor: 'pointer' }}
            onClick={() => setSelectedAlert(alert)}
          >
            <div className="d-flex w-100 justify-content-between">
              <h5 className="mb-1">
                <div dangerouslySetInnerHTML={{ __html: highlightKeywords(alert.title, keywords) }}></div>
              </h5>
              <small>{new Date(alert.pub_date).toLocaleString()}</small>
            </div>
          </div>
        ))}
      </div>
      <div className="pagination-bar">
        <div className="mt-3 d-flex justify-content-center">
          <Button variant="secondary" disabled={currentPage === 1} onClick={() => setCurrentPage(currentPage - 1)}>Previous</Button>
          <Dropdown onSelect={(selectedPage) => setCurrentPage(Number(selectedPage))} className="mx-2">
            <Dropdown.Toggle variant="secondary" id="dropdown-basic">
              Page {currentPage} of {totalPages}
            </Dropdown.Toggle>

            <Dropdown.Menu>
              {[...Array(totalPages).keys()].map((_, index) => (
                <Dropdown.Item key={index} eventKey={index + 1}>
                  {index + 1}
                </Dropdown.Item>
              ))}
            </Dropdown.Menu>
          </Dropdown>
          <Button variant="secondary" disabled={currentPage === totalPages} onClick={() => setCurrentPage(currentPage + 1)}>Next</Button>
        </div>
      </div>
        <br /><br />

      {selectedAlert && (
        <Modal show={selectedAlert !== null} onHide={handleCloseModal} size="xl">
          <Modal.Header closeButton>
            <Modal.Title>
              <span dangerouslySetInnerHTML={{ __html: highlightKeywords(selectedAlert.title, keywords) }}></span>  
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
