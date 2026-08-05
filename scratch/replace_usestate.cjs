const fs = require('fs');
const path = require('path');

function processFile(filePath) {
    let content = fs.readFileSync(filePath, 'utf8');

    // Regex to match the API and field configurations.
    // We only target specific state names to avoid replacing UI states.
    const stateNamesToPersist = [
        'apiUrl', 'username', 'password', 'indexPattern',
        'eventCodeField', 'parentNameField', 'parentPidField', 'processNameField', 'processPidField',
        
        'evt3CodeField', 'evt3CodeValue', 'evt3ProcessNameField', 'evt3ProcessPidField', 'evt3ExtraField',
        'evt11CodeField', 'evt11CodeValue', 'evt11ProcessNameField', 'evt11ProcessPidField', 'evt11ExtraField',
        'evt22CodeField', 'evt22CodeValue', 'evt22ProcessNameField', 'evt22ProcessPidField', 'evt22ExtraField',
        'evt13CodeField', 'evt13CodeValue', 'evt13ProcessNameField', 'evt13ProcessPidField', 'evt13ExtraField',
        'evt4104CodeField', 'evt4104CodeValue', 'evt4104ProcessPidField', 'evt4104ExtraField',
        
        'logonEventCodeField', 'logonProcessNameField', 'logonProcessPidField', 'logonIdField', 
        'logonHostField', 'logonSourceIpField', 'logonUserField', 'logonTypeField'
    ];

    stateNamesToPersist.forEach(name => {
        // e.g. const [apiUrl, setApiUrl] = useState('http://10.48.144.79:9200');
        const regex = new RegExp(`const\\s+\\[${name},\\s+set[A-Za-z0-9]+\\]\\s*=\\s*useState\\((.*?)\\);`, 'g');
        content = content.replace(regex, (match, initialValue) => {
            const setterName = 'set' + name.charAt(0).toUpperCase() + name.slice(1);
            return `const [${name}, ${setterName}] = useSessionStorage(storagePrefix + '${name}', ${initialValue});`;
        });
    });

    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`Processed ${filePath}`);
}

processFile(path.join(__dirname, '../src/components/ElasticApiView.jsx'));
processFile(path.join(__dirname, '../src/components/SplunkApiView.jsx'));
