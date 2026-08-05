import { useState, useRef, useEffect } from 'react';
import ElasticView from './components/ElasticView';
import SplunkView from './components/SplunkView';
import ElasticApiView from './components/ElasticApiView';
import SplunkApiView from './components/SplunkApiView';
import PatternLibrary from './components/PatternLibrary';
import './App.css';

const useSessionStorage = (key, initialValue) => {
  const [value, setValue] = useState(() => {
    try {
      const item = window.sessionStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      return initialValue;
    }
  });
  useEffect(() => {
    try {
      window.sessionStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.warn("sessionStorage limit exceeded");
    }
  }, [key, value]);
  return [value, setValue];
};

function App() {
  const [platform, setPlatform] = useSessionStorage('app_platform', 'elastic');
  const [isPatternLibraryOpen, setIsPatternLibraryOpen] = useState(false);
  const fileInputRef = useRef(null);

  const handleExport = () => {
    const sessionData = {};
    for (let i = 0; i < window.sessionStorage.length; i++) {
      const key = window.sessionStorage.key(i);
      sessionData[key] = window.sessionStorage.getItem(key);
    }
    const jsonString = JSON.stringify(sessionData, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    let filename = window.prompt("Nhập tên file để lưu (để trống sẽ tự động lấy thời gian hiện tại):");
    if (filename === null) return; // User cancelled
    
    if (!filename.trim()) {
      const now = new Date();
      const pad = (n) => n.toString().padStart(2, '0');
      filename = `session_${now.getFullYear()}${pad(now.getMonth()+1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}.json`;
    } else if (!filename.endsWith('.json')) {
      filename += '.json';
    }

    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleImport = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const sessionData = JSON.parse(event.target.result);
        window.sessionStorage.clear();
        for (const [key, value] of Object.entries(sessionData)) {
          window.sessionStorage.setItem(key, value);
        }
        window.location.reload();
      } catch (error) {
        alert("File không hợp lệ hoặc bị lỗi!");
        console.error("Error importing session:", error);
      }
    };
    reader.readAsText(file);
    e.target.value = ''; // Reset input
  };

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

          <button 
            onClick={handleExport}
            style={{ padding: '8px 15px', backgroundColor: 'rgba(16, 185, 129, 0.1)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '5px', transition: 'all 0.2s', marginLeft: '5px' }}
            onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'rgba(16, 185, 129, 0.2)'; }}
            onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'rgba(16, 185, 129, 0.1)'; }}
            title="Lưu toàn bộ phiên làm việc hiện tại"
          >
            <span>💾</span> Export Session
          </button>

          <button 
            onClick={() => fileInputRef.current.click()}
            style={{ padding: '8px 15px', backgroundColor: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '5px', transition: 'all 0.2s', marginLeft: '5px' }}
            onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'rgba(245, 158, 11, 0.2)'; }}
            onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'rgba(245, 158, 11, 0.1)'; }}
            title="Khôi phục phiên làm việc từ file đã lưu"
          >
            <span>📂</span> Import Session
          </button>
          <input 
            type="file" 
            accept=".json" 
            ref={fileInputRef} 
            style={{ display: 'none' }} 
            onChange={handleImport}
          />
          
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
