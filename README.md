# PashuAarogyam - Smart Animal Disease Prediction

A Flask web application that provides AI-powered animal disease prediction and veterinary guidance.

## Features

- **Disease Prediction**: Upload photos or input symptoms to predict animal diseases
- **Multiple Animal Support**: Cattle, pigs, chickens, sheep, goats, horses, dogs, and cats
- **Professional UI**: Modern, responsive design with smooth animations
- **File Upload**: Support for animal photos (JPG, PNG, WebP)
- **Health Recommendations**: Detailed care recommendations based on predictions
- **Mobile Responsive**: Works perfectly on all device sizes

## Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application**
   ```bash
   python app.py
   ```

3. **Open Your Browser**
   - Navigate to `http://localhost:5000`
   - Start using the disease prediction tool!

## Project Structure

```
GoRakhaAI/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html        # Main landing page
├── static/
│   ├── css/
│   │   └── style.css     # Main stylesheet
│   ├── js/
│   │   └── main.js       # JavaScript functionality
│   └── uploads/          # Uploaded images directory
└── README.md
```

## How It Works

1. **Select Animal Type**: Choose from 8 supported animal types
2. **Input Symptoms**: Check relevant symptoms from the comprehensive list
3. **Add Details**: Provide age, weight, temperature, and additional information
4. **Upload Photo** (Optional): Add an animal photo for visual analysis
5. **Get Prediction**: Receive AI-powered disease prediction with confidence scores
6. **View Recommendations**: Get detailed care and treatment recommendations

## Technology Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML5, CSS3, JavaScript
- **Styling**: Modern CSS with animations and responsive design
- **File Handling**: Secure file uploads with validation

## Development

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run in development mode
python app.py
```

### Production Deployment
```bash
# Set environment to production
export FLASK_ENV=production

# Run with Gunicorn (recommended)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## API Endpoints

- `GET /` - Main landing page
- `POST /predict_disease` - Disease prediction endpoint
- `GET /about` - About page (placeholder)
- `GET /contact` - Contact page (placeholder)

## Features in Detail

### Disease Prediction Algorithm
The application uses a symptom-based scoring system to predict diseases:
- Each animal type has a specific disease database
- Symptoms are matched against known disease patterns
- Confidence scores are calculated based on symptom matches
- Results include disease name, confidence level, and severity

### Supported Animals & Diseases

**Cattle**: Bovine Respiratory Disease, Mastitis, Foot and Mouth Disease, Bloat, Milk Fever
**Pigs**: Swine Flu, PRRS, Salmonellosis, Pneumonia
**Chickens**: Avian Influenza, Newcastle Disease, Coccidiosis, Fowl Pox
**Sheep**: Scrapie, Foot Rot, Parasitic Infections, Pneumonia
**Goats**: Caprine Arthritis Encephalitis, Pneumonia, Internal Parasites, Ketosis
**Horses**: Equine Influenza, Colic, Laminitis, Strangles
**Dogs**: Parvovirus, Distemper, Kennel Cough, Hip Dysplasia
**Cats**: Feline Leukemia, Upper Respiratory Infection, Feline Distemper, UTI

### Security Features
- File type validation for uploads
- File size limits (16MB maximum)
- Secure filename handling
- Input validation and sanitization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please contact support@pashuaarogyam.com or create an issue in the repository.

## Disclaimer

This application is for educational and informational purposes only. Always consult with qualified veterinarians for proper animal healthcare and medical advice.