# YOLOv8 Models Directory

This directory should contain the trained YOLOv8 model files for disease detection.

## Required Model Files:

### 1. Cat Disease Detection Model
- **Filename**: `cat_disease_best.pt`
- **Description**: YOLOv8 model trained to detect diseases in cats
- **Expected Classes**: 
  - Healthy cats
  - Sick/diseased cats with specific conditions

### 2. Cow Disease Detection Model  
- **Filename**: `lumpy_disease_best.pt`
- **Description**: YOLOv8 model trained to detect lumpy skin disease in cattle
- **Expected Classes**:
  - Healthy cattle
  - Lumpy skin disease

## Model Training Information:

These models should be trained YOLOv8 detection models (.pt files) that can:
- Accept image inputs
- Return bounding box detections with class labels and confidence scores
- Be loaded using the `ultralytics.YOLO()` class

## Usage:

The models are automatically loaded by the Flask application when it starts. If a model file is missing, the corresponding detection endpoint will return an error message.

## File Structure:
```
models/
├── README.md                    # This file
├── cat_disease_best.pt         # Cat disease detection model (REQUIRED)
├── lumpy_disease_best.pt       # Cow lumpy disease model (REQUIRED)
└── [other model files]         # Future expansion for other animals
```

## Notes:
- Models must be compatible with ultralytics YOLOv8
- Supported image formats: JPG, PNG, WebP
- Maximum image size: 16MB
- Models are loaded once at application startup for better performance