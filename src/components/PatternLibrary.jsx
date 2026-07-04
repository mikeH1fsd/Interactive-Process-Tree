import { useState, useEffect } from 'react';

const DEFAULT_PATTERNS = [
  {
    id: 'pat_1',
    name: 'Hunting Mimikatz Execution',
    query: 'winlog.event_id: 1 AND process.command_line: (*mimikatz* OR *DumpCreds* OR *privilege\\:\\:debug* OR *sekurlsa\\:\\:*)',
    platform: 'elastic'
  },
  {
    id: 'pat_2',
    name: 'Suspicious PowerShell Download',
    query: 'EventCode: "4104" AND ScriptBlockText: (*Net.WebClient* OR *DownloadString* OR *DownloadFile* OR *Invoke-WebRequest*)',
    platform: 'splunk'
  }
];

export default function PatternLibrary({ isOpen, onClose, currentPlatform }) {
  const [patterns, setPatterns] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  
  const activeGroup = (currentPlatform && currentPlatform.includes('splunk')) ? 'splunk' : 'elastic';
  
  // Add/Edit Form State
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [formName, setFormName] = useState('');
  const [formQuery, setFormQuery] = useState('');

  // Load from localStorage on mount
  useEffect(() => {
    const saved = localStorage.getItem('threat_hunt_patterns');
    if (saved) {
      try {
        setPatterns(JSON.parse(saved));
      } catch (e) {
        setPatterns(DEFAULT_PATTERNS);
      }
    } else {
      setPatterns(DEFAULT_PATTERNS);
      localStorage.setItem('threat_hunt_patterns', JSON.stringify(DEFAULT_PATTERNS));
    }
  }, []);

  // Save to localStorage when patterns change
  useEffect(() => {
    if (patterns.length > 0) {
      localStorage.setItem('threat_hunt_patterns', JSON.stringify(patterns));
    }
  }, [patterns]);

  const handleCopy = (query) => {
    navigator.clipboard.writeText(query);
    alert('Đã copy câu query!');
  };

  const handleDelete = (id) => {
    if (confirm('Bạn có chắc muốn xóa pattern này?')) {
      setPatterns(prev => prev.filter(p => p.id !== id));
    }
  };

  const handleEdit = (pat) => {
    setEditingId(pat.id);
    setFormName(pat.name);
    setFormQuery(pat.query);
    setIsFormOpen(true);
  };

  const handleSaveForm = () => {
    if (!formName.trim() || !formQuery.trim()) {
      alert('Vui lòng nhập đủ Tên và Câu Query!');
      return;
    }

    if (editingId) {
      setPatterns(prev => prev.map(p => 
        p.id === editingId 
          ? { ...p, name: formName, query: formQuery, platform: activeGroup } 
          : p
      ));
    } else {
      const newPat = {
        id: 'pat_' + Date.now(),
        name: formName,
        query: formQuery,
        platform: activeGroup
      };
      setPatterns(prev => [newPat, ...prev]);
    }
    
    // Reset form
    setEditingId(null);
    setFormName('');
    setFormQuery('');
    setIsFormOpen(false);
  };

  const filteredPatterns = patterns.filter(p => {
    const matchesPlatform = p.platform === activeGroup;
    const matchesSearch = p.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          p.query.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesPlatform && matchesSearch;
  });

  return (
    <>
      {/* Backdrop overlay */}
      <div 
        onClick={onClose}
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.5)',
          zIndex: 9999,
          opacity: isOpen ? 1 : 0,
          pointerEvents: isOpen ? 'auto' : 'none',
          transition: 'opacity 0.3s ease'
        }}
      />
      
      {/* Drawer */}
      <div style={{
        position: 'fixed',
        top: 0,
        right: 0,
        bottom: 0,
        width: '450px',
        maxWidth: '100vw',
        backgroundColor: 'var(--panel-bg)',
        borderLeft: '1px solid var(--panel-border)',
        zIndex: 10000,
        transform: isOpen ? 'translateX(0)' : 'translateX(100%)',
        transition: 'transform 0.3s ease',
        display: 'flex',
        flexDirection: 'column',
        boxShadow: '-4px 0 15px rgba(0,0,0,0.5)'
      }}>
        {/* Header */}
        <div style={{ padding: '20px', borderBottom: '1px solid var(--panel-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: 'var(--bg-color)' }}>
          <h2 style={{ margin: 0, fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>📚</span> Thư viện Patterns ({activeGroup === 'elastic' ? 'Elastic' : 'Splunk'})
          </h2>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', fontSize: '1.5rem', cursor: 'pointer', padding: '0 5px' }}>×</button>
        </div>

        {/* Search & Actions */}
        <div style={{ padding: '20px', borderBottom: '1px solid var(--panel-border)', display: 'flex', flexDirection: 'column', gap: '15px' }}>
          {!isFormOpen ? (
            <>
              <input 
                type="text" 
                placeholder="🔍 Tìm kiếm pattern theo tên hoặc query..." 
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{ width: '100%', padding: '10px 15px', borderRadius: '6px', border: '1px solid var(--panel-border)', backgroundColor: 'rgba(0,0,0,0.2)', color: 'var(--text-primary)', outline: 'none' }}
              />
              <button 
                onClick={() => { setIsFormOpen(true); setEditingId(null); setFormName(''); setFormQuery(''); }}
                style={{ width: '100%', padding: '10px', backgroundColor: '#10b981', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold' }}
              >
                + Thêm Pattern Mới
              </button>
            </>
          ) : (
            <div style={{ backgroundColor: 'rgba(0,0,0,0.2)', padding: '15px', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
              <h3 style={{ margin: '0 0 15px 0', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '5px' }}>
                 <span>{editingId ? '✏️' : '✨'}</span> {editingId ? 'Sửa Pattern' : 'Thêm Mới Pattern'}
              </h3>
              
              <label style={{ display: 'block', marginBottom: '5px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Tên Pattern:</label>
              <input 
                type="text" 
                value={formName}
                onChange={e => setFormName(e.target.value)}
                placeholder="VD: Hunting Mimikatz Execution"
                style={{ width: '100%', padding: '8px', marginBottom: '10px', borderRadius: '4px', border: '1px solid var(--panel-border)', backgroundColor: 'var(--panel-bg)', color: 'var(--text-primary)' }}
              />
              
              <label style={{ display: 'block', marginBottom: '5px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Câu Query:</label>
              <textarea 
                value={formQuery}
                onChange={e => setFormQuery(e.target.value)}
                placeholder="VD: winlog.event_id: 1 AND process.command_line: *mimikatz*"
                rows={4}
                style={{ width: '100%', padding: '8px', marginBottom: '15px', borderRadius: '4px', border: '1px solid var(--panel-border)', backgroundColor: 'var(--panel-bg)', color: 'var(--text-primary)', fontFamily: 'monospace', resize: 'vertical' }}
              />
              
              <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                <button onClick={() => setIsFormOpen(false)} style={{ padding: '8px 15px', background: 'transparent', border: '1px solid var(--panel-border)', color: 'var(--text-primary)', borderRadius: '4px', cursor: 'pointer' }}>Hủy</button>
                <button onClick={handleSaveForm} style={{ padding: '8px 15px', background: '#3b82f6', border: 'none', color: 'white', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}>Lưu</button>
              </div>
            </div>
          )}
        </div>

        {/* Pattern List */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
          {filteredPatterns.length === 0 ? (
            <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '20px' }}>
              Không tìm thấy pattern nào!
            </div>
          ) : (
            filteredPatterns.map(pat => (
              <div key={pat.id} style={{ 
                backgroundColor: 'rgba(255,255,255,0.03)', 
                border: '1px solid var(--panel-border)', 
                borderRadius: '8px', 
                padding: '15px',
                transition: 'border-color 0.2s',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                  <h4 style={{ margin: 0, color: 'var(--primary)', fontSize: '1rem', paddingRight: '10px', lineHeight: '1.4' }}>{pat.name}</h4>
                  <div style={{ display: 'flex', gap: '5px', flexShrink: 0 }}>
                    <button onClick={() => handleEdit(pat)} title="Sửa" style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: '2px', opacity: 0.7 }}>✏️</button>
                    <button onClick={() => handleDelete(pat.id)} title="Xóa" style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: '2px', opacity: 0.7 }}>🗑️</button>
                  </div>
                </div>
                
                <div style={{ 
                  backgroundColor: 'rgba(0,0,0,0.4)', 
                  padding: '10px', 
                  borderRadius: '6px', 
                  fontFamily: 'monospace', 
                  fontSize: '0.85rem',
                  color: '#fbbf24',
                  wordBreak: 'break-all',
                  marginBottom: '10px'
                }}>
                  {pat.query}
                </div>
                
                <button 
                  onClick={() => handleCopy(pat.query)}
                  style={{ width: '100%', padding: '6px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.3)', borderRadius: '4px', cursor: 'pointer', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '5px' }}
                >
                  <span>📋</span> Copy Query
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </>
  );
}
