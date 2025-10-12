// PashuAarogyam - Main JavaScript File

document.addEventListener('DOMContentLoaded', function() {
    // Initialize the application
    initializeContactForm();
    initializeSmoothScrolling();
});

// Contact form functionality
function initializeContactForm() {
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form data
            const formData = new FormData(contactForm);
            const data = Object.fromEntries(formData);
            
            // Show loading state
            const submitBtn = contactForm.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = 'Sending...';
            submitBtn.disabled = true;
            
            // Simulate form submission (replace with actual endpoint)
            setTimeout(() => {
                showAlert('Thank you for your message! We will get back to you soon.', 'success');
                contactForm.reset();
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
            }, 2000);
        });
    }
}

// Smooth scrolling for anchor links
function initializeSmoothScrolling() {
    const anchors = document.querySelectorAll('a[href^="#"]');
    
    anchors.forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Utility function to show alerts
function showAlert(message, type = 'info') {
    // Create alert element
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        background: ${type === 'success' ? '#d4edda' : type === 'error' ? '#f8d7da' : '#d1ecf1'};
        color: ${type === 'success' ? '#155724' : type === 'error' ? '#721c24' : '#0c5460'};
        border: 1px solid ${type === 'success' ? '#c3e6cb' : type === 'error' ? '#f5c6cb' : '#b6d4fe'};
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        z-index: 10000;
        font-family: inherit;
        max-width: 300px;
        animation: slideInRight 0.3s ease-out;
    `;
    alert.textContent = message;
    
    // Add to page
    document.body.appendChild(alert);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        alert.style.animation = 'slideOutRight 0.3s ease-in forwards';
        setTimeout(() => {
            if (document.body.contains(alert)) {
                document.body.removeChild(alert);
            }
        }, 300);
    }, 5000);
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
// document.head.appendChild(style);
//             }, 1500);
            
            // Uncomment for actual form submission:
            /*
            fetch('/contact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Thank you for your message! We will get back to you soon.', 'success');
                    contactForm.reset();
                } else {
                    showAlert('Error sending message. Please try again.', 'error');
                }
            })
            .catch(error => {
                showAlert('Error sending message. Please try again.', 'error');
            })
            .finally(() => {
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
            });
            */
//         });
//     }
// }

// Initialize smooth scrolling
function initializeSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Initialize prediction form
function initializePredictionForm() {
    const predictionForm = document.getElementById('predictionForm');
    
    if (predictionForm) {
        predictionForm.addEventListener('submit', function(e) {
            e.preventDefault();
            submitPredictionForm(this);
        });
    }
}

// Reset prediction form
function resetPredictionForm() {
    const form = document.getElementById('predictionForm');
    const resultDiv = document.getElementById('predictionResult');
    const loadingDiv = document.querySelector('.loading');
    
    if (form) {
        form.reset();
    }
    
    if (resultDiv) {
        resultDiv.style.display = 'none';
    }
    
    if (loadingDiv) {
        loadingDiv.style.display = 'none';
    }
    
    // Reset file upload area
    const fileUpload = document.querySelector('.file-upload');
    if (fileUpload && fileUpload.classList.contains('file-uploaded')) {
        fileUpload.innerHTML = `
            <p>📷 Click to upload photo</p>
            <small>Supported formats: JPG, PNG, WebP</small>
        `;
        fileUpload.classList.remove('file-uploaded');
    }
}

// Submit prediction form
function submitPredictionForm(form) {
    // Validate form
    const animalType = form.querySelector('[name="animal_type"]').value;
    if (!animalType) {
        showAlert('Please select an animal type', 'error');
        return;
    }
    
    // Show loading spinner
    document.querySelector('.loading').style.display = 'block';
    document.getElementById('predictionResult').style.display = 'none';
    
    // Get form data
    const formData = new FormData(form);
    
    // Get selected symptoms
    const symptoms = [];
    document.querySelectorAll('input[name="symptoms"]:checked').forEach(checkbox => {
        symptoms.push(checkbox.value);
    });
    formData.set('symptoms', JSON.stringify(symptoms));
    
    // Submit to Flask backend
    fetch('/predict_disease', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        document.querySelector('.loading').style.display = 'none';
        
        if (data.success) {
            displayPredictionResult(data.prediction);
        } else {
            showAlert('Error occurred during prediction: ' + (data.error || 'Unknown error'), 'error');
        }
    })
    .catch(error => {
        document.querySelector('.loading').style.display = 'none';
        console.error('Error:', error);
        showAlert('Error occurred during prediction. Please try again.', 'error');
        
        // Show a mock result for demo purposes if backend fails
        setTimeout(() => {
            const mockResult = generateMockPrediction(formData);
            displayPredictionResult(mockResult);
        }, 1000);
    });
}

// Display prediction result
function displayPredictionResult(prediction) {
    const resultContent = document.getElementById('resultContent');
    const resultDiv = document.getElementById('predictionResult');
    
    if (!resultContent || !resultDiv) return;
    
    // Format severity badge
    const severityClass = prediction.severity === 'High' ? 'alert-error' : 
                          prediction.severity === 'Medium' ? 'alert-warning' : 
                          'alert-success';
    
    const resultHTML = `
        <div style="margin-bottom: 1rem;">
            <strong>Most Likely Disease:</strong> ${prediction.disease}
        </div>
        <div style="margin-bottom: 1rem;">
            <strong>Confidence:</strong> ${prediction.confidence}%
            <div style="background: #e9ecef; border-radius: 10px; height: 8px; margin-top: 0.5rem;">
                <div style="background: ${prediction.confidence > 80 ? '#28a745' : prediction.confidence > 60 ? '#ffc107' : '#dc3545'}; 
                           width: ${prediction.confidence}%; height: 100%; border-radius: 10px;"></div>
            </div>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong>Severity Level:</strong> 
            <span class="alert ${severityClass}" style="display: inline-block; padding: 0.25rem 0.75rem; margin-left: 0.5rem;">
                ${prediction.severity}
            </span>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong>Animal Type:</strong> ${capitalizeFirst(prediction.animal_type)}
        </div>
        <div style="margin-bottom: 1rem;">
            <strong>Symptoms Analyzed:</strong> ${prediction.symptoms_analyzed.length > 0 ? prediction.symptoms_analyzed.map(s => capitalizeFirst(s.replace(/_/g, ' '))).join(', ') : 'None specified'}
        </div>
        <div style="margin-bottom: 1rem;">
            <strong>Recommendations:</strong>
            <ul style="margin-left: 1rem; margin-top: 0.5rem;">
                ${prediction.recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
        </div>
        <div class="alert alert-warning" style="margin-top: 1.5rem;">
            <strong>⚠️ Important Disclaimer:</strong> This AI prediction is for informational purposes only and should not replace professional veterinary diagnosis. Please consult with a qualified veterinarian for proper treatment and medical advice.
        </div>
        <div style="margin-top: 1rem; text-align: center;">
            <button class="btn btn-primary" onclick="printPrediction()" style="margin-right: 1rem;">
                🖨️ Print Results
            </button>
            <button class="btn btn-signup" onclick="resetPredictionForm()">
                🔄 New Prediction
            </button>
        </div>
    `;
    
    resultContent.innerHTML = resultHTML;
    resultDiv.style.display = 'block';
    
    // Scroll to result
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Generate mock prediction for demo
function generateMockPrediction(formData) {
    const animalType = formData.get('animal_type');
    const symptoms = JSON.parse(formData.get('symptoms') || '[]');
    
    const mockDiseases = {
        cattle: ['Bovine Respiratory Disease', 'Mastitis', 'Foot and Mouth Disease', 'Bloat', 'Milk Fever'],
        pig: ['Swine Flu', 'Porcine Reproductive and Respiratory Syndrome', 'Salmonellosis', 'Pneumonia'],
        chicken: ['Avian Influenza', 'Newcastle Disease', 'Coccidiosis', 'Fowl Pox'],
        sheep: ['Scrapie', 'Foot Rot', 'Parasitic Infections', 'Pneumonia'],
        goat: ['Caprine Arthritis Encephalitis', 'Pneumonia', 'Internal Parasites', 'Ketosis'],
        horse: ['Equine Influenza', 'Colic', 'Laminitis', 'Strangles'],
        dog: ['Parvovirus', 'Distemper', 'Kennel Cough', 'Hip Dysplasia'],
        cat: ['Feline Leukemia', 'Upper Respiratory Infection', 'Feline Distemper', 'Urinary Tract Infection']
    };
    
    const diseases = mockDiseases[animalType] || ['General Infection', 'Nutritional Deficiency', 'Stress-related Condition'];
    const selectedDisease = diseases[Math.floor(Math.random() * diseases.length)];
    const confidence = (75 + Math.random() * 20).toFixed(1);
    const severity = confidence > 85 ? 'High' : confidence > 65 ? 'Medium' : 'Low';
    
    const recommendations = [
        "Consult with a veterinarian immediately for proper diagnosis",
        "Monitor the animal's condition closely",
        "Ensure proper nutrition and hydration",
        "Keep the animal comfortable and reduce stress"
    ];
    
    if (symptoms.includes('fever')) {
        recommendations.push("Monitor body temperature regularly");
    }
    if (symptoms.includes('diarrhea') || symptoms.includes('vomiting')) {
        recommendations.push("Ensure adequate fluid intake to prevent dehydration");
    }
    if (symptoms.includes('difficulty_breathing')) {
        recommendations.push("Ensure good ventilation and avoid stress");
    }
    
    return {
        disease: selectedDisease,
        confidence: parseFloat(confidence),
        symptoms_analyzed: symptoms,
        recommendations: recommendations,
        severity: severity,
        animal_type: animalType
    };
}

// Utility functions
function capitalizeFirst(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function showAlert(message, type) {
    // Remove existing alerts
    const existingAlerts = document.querySelectorAll('.alert-notification');
    existingAlerts.forEach(alert => alert.remove());
    
    // Create new alert
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'error' : type === 'success' ? 'success' : 'warning'} alert-notification`;
    alertDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 3000;
        max-width: 400px;
        border-radius: 8px;
        padding: 1rem 1.5rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        animation: slideInRight 0.3s ease;
    `;
    
    alertDiv.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; font-size: 1.2rem; cursor: pointer; color: inherit; margin-left: 1rem;">×</button>
        </div>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

// Print prediction results
window.printPrediction = function() {
    const resultContent = document.getElementById('resultContent');
    if (!resultContent) return;
    
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <html>
        <head>
            <title>PashuAarogyam - Disease Prediction Report</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; line-height: 1.6; }
                .header { text-align: center; margin-bottom: 30px; }
                .alert { padding: 10px; border-radius: 5px; margin: 10px 0; }
                .alert-warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
                ul { margin-left: 20px; }
                .no-print { display: none; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🐾 PashuAarogyam</h1>
                <h2>Disease Prediction Report</h2>
                <p>Generated on ${new Date().toLocaleString()}</p>
            </div>
            ${resultContent.innerHTML.replace(/onclick="[^"]*"/g, '').replace(/<button[^>]*>.*?<\/button>/gs, '')}
        </body>
        </html>
    `);
    printWindow.document.close();
    printWindow.print();
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    .file-uploaded {
        background-color: #f8f9fa !important;
        border-color: #3CB371 !important;
    }
    
    .file-uploaded p {
        color: #3CB371;
        font-weight: bold;
    }
`;
document.head.appendChild(style);