import React, { useState, useRef, useEffect } from 'react';

function AutocompleteInput({ value, onChange, placeholder, suggestions = [], multi = false }) {
  const [showDropdown, setShowDropdown] = useState(false);
  const wrapperRef = useRef(null);

  const currentTerm = multi ? value.split(',').pop().trim() : value.trim();
  const filteredFields = suggestions.filter(f => f.toLowerCase().includes(currentTerm.toLowerCase()) && f !== currentTerm).slice(0, 100);

  const handleSelect = (field) => {
    if (multi) {
      const parts = value.split(',');
      parts[parts.length - 1] = (parts.length > 1 ? ' ' : '') + field;
      onChange(parts.join(','));
    } else {
      onChange(field);
    }
    setShowDropdown(false);
  };

  useEffect(() => {
    function handleClickOutside(event) {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target)) {
        setShowDropdown(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [wrapperRef]);

  return (
    <div className="autocomplete-container" ref={wrapperRef}>
      <input
        type="text"
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
          setShowDropdown(true);
        }}
        onFocus={() => setShowDropdown(true)}
        placeholder={placeholder}
      />
      {showDropdown && filteredFields.length > 0 && (
        <div className="autocomplete-dropdown">
          {filteredFields.map(field => (
            <div 
              key={field} 
              className="autocomplete-item"
              title={field}
              onClick={() => handleSelect(field)}
            >
              {field}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default AutocompleteInput;
