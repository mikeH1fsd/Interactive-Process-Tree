import { useState } from 'react';
import ElasticView from './components/ElasticView';
import SplunkView from './components/SplunkView';
import './App.css';

function App() {
  const [platform, setPlatform] = useState('elastic');

  return (
    <div className="container">
      <header>
        <h1>Interactive Process Tree Builder</h1>
        <p>Giao diện Full Screen - Mở Rộng Nhánh Liên Tục</p>
      </header>
      
      <div style={{ padding: '0 20px', marginBottom: '20px' }}>
        <section className="card" style={{ maxWidth: '400px', margin: '0 auto' }}>
          <h2 style={{ textAlign: 'center', marginTop: 0 }}>Nền Tảng SIEM</h2>
          <div style={{ display: 'flex', gap: '15px', justifyContent: 'center' }}>
            <label style={{ cursor: 'pointer' }}>
              <input 
                type="radio" 
                name="platform" 
                value="elastic" 
                checked={platform === 'elastic'} 
                onChange={(e) => setPlatform(e.target.value)} 
              />
              {' '}Elastic (KQL)
            </label>
            <label style={{ cursor: 'pointer' }}>
              <input 
                type="radio" 
                name="platform" 
                value="splunk" 
                checked={platform === 'splunk'} 
                onChange={(e) => setPlatform(e.target.value)} 
              />
              {' '}Splunk (SPL)
            </label>
          </div>
        </section>
      </div>

      {platform === 'elastic' ? <ElasticView /> : <SplunkView />}
    </div>
  );
}

export default App;
