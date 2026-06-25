import re

with open('src/components/ElasticApiView.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Config block replacement
config_start = """        <div className="card">
          <h2 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Cấu Hình Fields</span>
            <span style={{ fontSize: '0.8rem', fontWeight: 'normal', color: 'var(--text-secondary)' }}>
              {indexFields.length} fields đã tải
            </span>
          </h2>"""

config_end = """          <div className="input-group">
            <label>Logon Type Field:</label>
            <AutocompleteInput value={logonTypeField} onChange={setLogonTypeField} placeholder="winlog.event_data.LogonType" suggestions={indexFields} />
          </div>
        </div>"""

new_config = """        <div className="card">
          <h2 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <span>Cấu Hình Event Fields</span>
            <span style={{ fontSize: '0.8rem', fontWeight: 'normal', color: 'var(--text-secondary)' }}>
              {indexFields.length} fields
            </span>
          </h2>

          <div onClick={() => setOpenConfig(openConfig === 'process' ? '' : 'process')} style={{ padding: '10px', backgroundColor: openConfig === 'process' ? 'rgba(255,255,255,0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid var(--panel-border)', borderBottom: openConfig === 'process' ? 'none' : '1px solid var(--panel-border)', borderRadius: openConfig === 'process' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'process' ? '0' : '10px' }}>
            <strong>⚙️ Process (Event 1, 4688)</strong><span>{openConfig === 'process' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'process' && (
            <div style={{ padding: '15px', border: '1px solid var(--panel-border)', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={eventCodeField} onChange={setEventCodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Parent Name:</label><AutocompleteInput value={parentNameField} onChange={setParentNameField} placeholder="process.parent.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Parent PID:</label><AutocompleteInput value={parentPidField} onChange={setParentPidField} placeholder="process.parent.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={processNameField} onChange={setProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={processPidField} onChange={setProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (Tuỳ chọn):</label><AutocompleteInput value={extraField} onChange={setExtraField} placeholder="Ví dụ: process.command_line..." suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'network' ? '' : 'network')} style={{ padding: '10px', backgroundColor: openConfig === 'network' ? 'rgba(56, 189, 248, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #38bdf8', borderBottom: openConfig === 'network' ? 'none' : '1px solid #38bdf8', borderRadius: openConfig === 'network' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'network' ? '0' : '10px', color: '#38bdf8' }}>
            <strong>📡 Network (Event 3)</strong><span>{openConfig === 'network' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'network' && (
            <div style={{ padding: '15px', border: '1px solid #38bdf8', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt3CodeField} onChange={setEvt3CodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={evt3ProcessNameField} onChange={setEvt3ProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={evt3ProcessPidField} onChange={setEvt3ProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (Network data):</label><AutocompleteInput value={evt3ExtraField} onChange={setEvt3ExtraField} placeholder="destination.ip, destination.port" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'file' ? '' : 'file')} style={{ padding: '10px', backgroundColor: openConfig === 'file' ? 'rgba(244, 114, 182, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #f472b6', borderBottom: openConfig === 'file' ? 'none' : '1px solid #f472b6', borderRadius: openConfig === 'file' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'file' ? '0' : '10px', color: '#f472b6' }}>
            <strong>📁 File (Event 11)</strong><span>{openConfig === 'file' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'file' && (
            <div style={{ padding: '15px', border: '1px solid #f472b6', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt11CodeField} onChange={setEvt11CodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={evt11ProcessNameField} onChange={setEvt11ProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={evt11ProcessPidField} onChange={setEvt11ProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (File data):</label><AutocompleteInput value={evt11ExtraField} onChange={setEvt11ExtraField} placeholder="file.path" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'dns' ? '' : 'dns')} style={{ padding: '10px', backgroundColor: openConfig === 'dns' ? 'rgba(6, 182, 212, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #06b6d4', borderBottom: openConfig === 'dns' ? 'none' : '1px solid #06b6d4', borderRadius: openConfig === 'dns' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'dns' ? '0' : '10px', color: '#06b6d4' }}>
            <strong>🌐 DNS (Event 22)</strong><span>{openConfig === 'dns' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'dns' && (
            <div style={{ padding: '15px', border: '1px solid #06b6d4', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt22CodeField} onChange={setEvt22CodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={evt22ProcessNameField} onChange={setEvt22ProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={evt22ProcessPidField} onChange={setEvt22ProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (DNS Question):</label><AutocompleteInput value={evt22ExtraField} onChange={setEvt22ExtraField} placeholder="dns.question.name" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'registry' ? '' : 'registry')} style={{ padding: '10px', backgroundColor: openConfig === 'registry' ? 'rgba(251, 146, 60, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #fb923c', borderBottom: openConfig === 'registry' ? 'none' : '1px solid #fb923c', borderRadius: openConfig === 'registry' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'registry' ? '0' : '10px', color: '#fb923c' }}>
            <strong>🗄️ Registry (Event 13)</strong><span>{openConfig === 'registry' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'registry' && (
            <div style={{ padding: '15px', border: '1px solid #fb923c', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt13CodeField} onChange={setEvt13CodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={evt13ProcessNameField} onChange={setEvt13ProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={evt13ProcessPidField} onChange={setEvt13ProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (Registry Path):</label><AutocompleteInput value={evt13ExtraField} onChange={setEvt13ExtraField} placeholder="registry.path" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'powershell' ? '' : 'powershell')} style={{ padding: '10px', backgroundColor: openConfig === 'powershell' ? 'rgba(37, 99, 235, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #2563eb', borderBottom: openConfig === 'powershell' ? 'none' : '1px solid #2563eb', borderRadius: openConfig === 'powershell' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'powershell' ? '0' : '10px', color: '#2563eb' }}>
            <strong>📜 PowerShell (Event 4104)</strong><span>{openConfig === 'powershell' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'powershell' && (
            <div style={{ padding: '15px', border: '1px solid #2563eb', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt4104CodeField} onChange={setEvt4104CodeField} placeholder="winlog.event_id" suggestions={indexFields} /></div>
              <div className="input-group"><label>Event Value:</label><input type="text" value={evt4104CodeValue} onChange={e => setEvt4104CodeValue(e.target.value)} /></div>
              <div className="input-group"><label>Process PID Field:</label><AutocompleteInput value={evt4104ProcessPidField} onChange={setEvt4104ProcessPidField} placeholder="winlog.process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (Script Block):</label><AutocompleteInput value={evt4104ExtraField} onChange={setEvt4104ExtraField} placeholder="powershell.file.script_block_text" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'logon' ? '' : 'logon')} style={{ padding: '10px', backgroundColor: openConfig === 'logon' ? 'rgba(245, 158, 11, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #f59e0b', borderBottom: openConfig === 'logon' ? 'none' : '1px solid #f59e0b', borderRadius: openConfig === 'logon' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'logon' ? '0' : '10px', color: '#f59e0b' }}>
            <strong>👤 Logon Context (4688 ➔ 4624)</strong><span>{openConfig === 'logon' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'logon' && (
            <div style={{ padding: '15px', border: '1px solid #f59e0b', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '0' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={logonEventCodeField} onChange={setLogonEventCodeField} placeholder="winlog.event_id" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name Field:</label><AutocompleteInput value={logonProcessNameField} onChange={setLogonProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID Field:</label><AutocompleteInput value={logonProcessPidField} onChange={setLogonProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Logon ID Field:</label><AutocompleteInput value={logonIdField} onChange={setLogonIdField} placeholder="winlog.logon.id" suggestions={indexFields} /></div>
              <div className="input-group"><label>Hostname Field:</label><AutocompleteInput value={logonHostField} onChange={setLogonHostField} placeholder="host.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Source IP Field:</label><AutocompleteInput value={logonSourceIpField} onChange={setLogonSourceIpField} placeholder="source.ip" suggestions={indexFields} /></div>
              <div className="input-group"><label>User Name Field:</label><AutocompleteInput value={logonUserField} onChange={setLogonUserField} placeholder="user.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Logon Type Field:</label><AutocompleteInput value={logonTypeField} onChange={setLogonTypeField} placeholder="winlog.event_data.LogonType" suggestions={indexFields} /></div>
            </div>
          )}
        </div>"""

content = content.replace(config_start, new_config)
# Handle the part that we replaced starting with config_start and ending with config_end
start_idx = content.find(new_config)
if start_idx != -1:
    end_idx = content.find(config_end, start_idx)
    if end_idx != -1:
        content = content[:start_idx + len(new_config)] + content[end_idx + len(config_end):]

# 2. Buttons block replacement
btn_start = """            <button 
              onClick={handleBuild} 
              disabled={isBuilding}
              style={{ flex: 1, backgroundColor: isBuilding ? 'var(--text-secondary)' : 'var(--primary)' }}
            >
              {isBuilding ? '⏳ Đang xử lý...' : (Object.keys(nodes).length === 0 ? '🚀 Build Cây Mới' : '🔍 Auto Bulk Expand')}
            </button>"""

btn_end = """            <button 
              onClick={() => setNodes({})} 
              style={{ width: 'auto', backgroundColor: '#da3633' }}
            >
              🗑️ Xóa toàn bộ
            </button>
          </div>"""

new_btn = """            <button 
              onClick={handleBuild} 
              disabled={isBuilding}
              style={{ flex: 1, backgroundColor: isBuilding ? 'var(--text-secondary)' : 'var(--primary)' }}
            >
              {isBuilding ? '⏳ Đang xử lý...' : (Object.keys(nodes).length === 0 ? '🚀 Build Cây Mới' : '🔍 Auto Bulk Expand')}
            </button>
            {Object.keys(nodes).length > 0 && (
              <div style={{ position: 'relative' }}>
                <button 
                  onClick={() => setShowActionModal(!showActionModal)}
                  style={{ width: 'auto', backgroundColor: 'var(--panel-bg)', color: 'var(--text-primary)', border: '1px solid var(--panel-border)', padding: '10px 15px' }}
                >
                  🛠️ Các chức năng quét {showActionModal ? '▲' : '▼'}
                </button>
                {showActionModal && (
                  <div style={{ position: 'absolute', top: '100%', left: 0, marginTop: '5px', backgroundColor: 'var(--panel-bg)', border: '1px solid var(--panel-border)', borderRadius: '6px', padding: '10px', display: 'flex', flexDirection: 'column', gap: '8px', zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', width: '280px' }}>
                    <button onClick={() => { handleFetchLogonContext(); setShowActionModal(false); }} disabled={isFetchingLogon} style={{ backgroundColor: '#f59e0b', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      👤 Tra cứu Logon Context
                    </button>
                    <button onClick={() => { handleBulkFetchNetwork(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#0ea5e9', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      📡 Quét toàn bộ Network (Event 3)
                    </button>
                    <button onClick={() => { handleBulkFetchFile(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#db2777', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      📁 Quét toàn bộ File (Event 11)
                    </button>
                    <button onClick={() => { handleBulkFetchDns(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#06b6d4', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      🌐 Quét toàn bộ DNS (Event 22)
                    </button>
                    <button onClick={() => { handleBulkFetchRegistry(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#fb923c', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      🗄️ Quét toàn bộ Registry (Event 13)
                    </button>
                    <button onClick={() => { handleBulkFetchPowerShell(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#2563eb', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      📜 Dịch PowerShell (Event 4104)
                    </button>
                    <div style={{ height: '1px', backgroundColor: 'var(--panel-border)', margin: '4px 0' }}></div>
                    <button onClick={() => { handleGeneratePrompt(); setShowActionModal(false); }} style={{ backgroundColor: '#8b5cf6', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      🤖 Tạo Prompt AI
                    </button>
                    <button onClick={() => { handlePruneSpam(); setShowActionModal(false); }} style={{ backgroundColor: '#eab308', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      ✂️ Dọn Spam & Tối ưu cây
                    </button>
                  </div>
                )}
              </div>
            )}
            <button 
              onClick={() => { setNodes({}); setLogonContext(null); setWorkspaces([{ id: 'root', name: '🌳 Cây Gốc', isDownwardOnly: false }]); setActiveWorkspaceId('root'); setWorkspaceData({'root': {}}); }} 
              style={{ width: 'auto', backgroundColor: '#da3633', marginLeft: 'auto' }}
            >
              🗑️ Xóa toàn bộ
            </button>
          </div>"""

start_idx_btn = content.find(btn_start)
if start_idx_btn != -1:
    end_idx_btn = content.find(btn_end, start_idx_btn)
    if end_idx_btn != -1:
        content = content[:start_idx_btn] + new_btn + content[end_idx_btn + len(btn_end):]

with open('src/components/ElasticApiView.jsx', 'w', encoding='utf-8') as f:
    f.write(content)
print("Updated successfully")
