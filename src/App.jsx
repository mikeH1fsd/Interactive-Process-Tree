import { useState } from 'react';
import ElasticView from './components/ElasticView';
import SplunkView from './components/SplunkView';
import ElasticApiView from './components/ElasticApiView';
import SplunkApiView from './components/SplunkApiView';
import PatternLibrary from './components/PatternLibrary';
import './App.css';

function App() {
  const [platform, setPlatform] = useState('elastic');
  const [isPatternLibraryOpen, setIsPatternLibraryOpen] = useState(false);

  return (
    <div className="container">
      <header className="app-header">
        <div className="title-group">
          <h1>Threat Hunt Builder</h1>
        </div>
        
        <div className="platform-selector" style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <button 
            onClick={() => setIsPatternLibraryOpen(true)}
            style={{ padding: '8px 15px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.3)', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '5px', transition: 'all 0.2s' }}
            onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.2)'; }}
            onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.1)'; }}
          >
            <span>📚</span> Thư viện Patterns
          </button>
          
          <div style={{ display: 'flex', gap: '10px', marginLeft: '10px' }}>
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
        </div>
      </header>

      <div style={{ display: platform === 'elastic' ? 'block' : 'none' }}>
        <ElasticApiView isManualMode={true} />
      </div>
      <div style={{ display: platform === 'splunk' ? 'block' : 'none' }}>
        <SplunkApiView isManualMode={true} />
      </div>
      <div style={{ display: platform === 'elastic_api' ? 'block' : 'none' }}>
        <ElasticApiView />
      </div>
      <div style={{ display: platform === 'splunk_api' ? 'block' : 'none' }}>
        <SplunkApiView />
      </div>

      <PatternLibrary 
        isOpen={isPatternLibraryOpen} 
        onClose={() => setIsPatternLibraryOpen(false)}
        currentPlatform={platform}
      />
    </div>
  );
}

export default App;
