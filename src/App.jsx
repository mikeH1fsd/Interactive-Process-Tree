import { useState } from 'react';
import ElasticView from './components/ElasticView';
import SplunkView from './components/SplunkView';
import ElasticApiView from './components/ElasticApiView';
import SplunkApiView from './components/SplunkApiView';
import './App.css';

function App() {
  const [platform, setPlatform] = useState('elastic');

  return (
    <div className="container">
      <header className="app-header">
        <div className="title-group">
          <h1>Threat Hunt Builder</h1>
          <p>Interactive Process Tree & Visual Analyzer</p>
        </div>
        
        <div className="platform-selector">
          <label className={platform === 'elastic' ? 'active' : ''}>
            <input type="radio" name="platform" value="elastic" checked={platform === 'elastic'} onChange={(e) => setPlatform(e.target.value)} />
            Elastic (Copy/Paste)
          </label>
          <label className={platform === 'elastic_api' ? 'active' : ''}>
            <input type="radio" name="platform" value="elastic_api" checked={platform === 'elastic_api'} onChange={(e) => setPlatform(e.target.value)} />
            Elastic API
          </label>
          <label className={platform === 'splunk' ? 'active' : ''}>
            <input type="radio" name="platform" value="splunk" checked={platform === 'splunk'} onChange={(e) => setPlatform(e.target.value)} />
            Splunk (Copy/Paste)
          </label>
          <label className={platform === 'splunk_api' ? 'active' : ''}>
            <input type="radio" name="platform" value="splunk_api" checked={platform === 'splunk_api'} onChange={(e) => setPlatform(e.target.value)} />
            Splunk API
          </label>
        </div>
      </header>

      <div style={{ display: platform === 'elastic' ? 'block' : 'none' }}>
        <ElasticView />
      </div>
      <div style={{ display: platform === 'splunk' ? 'block' : 'none' }}>
        <SplunkView />
      </div>
      <div style={{ display: platform === 'elastic_api' ? 'block' : 'none' }}>
        <ElasticApiView />
      </div>
      <div style={{ display: platform === 'splunk_api' ? 'block' : 'none' }}>
        <SplunkApiView />
      </div>
    </div>
  );
}

export default App;
