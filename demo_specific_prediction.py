#!/usr/bin/env python3
"""
Demo script for Specific Disease Prediction Feature
This script demonstrates how to use the new specific disease prediction functionality
"""

import requests
import json

def demo_specific_prediction():
    """Demonstrate the specific disease prediction feature"""
    
    print("🎯 PashuAarogyam - Specific Disease Prediction Demo")
    print("=" * 50)
    
    # Demo data for testing
    demo_cases = [
        {
            "name": "Cattle with Respiratory Issues",
            "data": {
                "animal_type": "cattle",
                "animal_age": "3 years",
                "animal_weight": "450 kg",
                "animal_breed": "Holstein",
                "symptoms[]": ["coughing", "difficulty breathing", "nasal discharge", "fever"],
                "additional_symptoms": "Animal seems lethargic and has reduced appetite",
                "symptom_duration": "3-7 days",
                "severity": "moderate",
                "recent_changes": "Recently moved to new pasture area",
                "previous_treatment": "None administered yet"
            }
        },
        {
            "name": "Dog with Digestive Problems",
            "data": {
                "animal_type": "dog",
                "animal_age": "5 years",
                "animal_weight": "25 kg",
                "animal_breed": "Labrador",
                "symptoms[]": ["vomiting", "diarrhea", "loss of appetite", "lethargy"],
                "additional_symptoms": "Has been refusing favorite treats, seems uncomfortable",
                "symptom_duration": "1-2 days",
                "severity": "moderate",
                "recent_changes": "Changed to new dog food brand 3 days ago",
                "previous_treatment": "Withheld food for 12 hours as recommended"
            }
        },
        {
            "name": "Cat with Urinary Issues",
            "data": {
                "animal_type": "cat",
                "animal_age": "7 years",
                "animal_weight": "4.5 kg",
                "animal_breed": "Persian",
                "symptoms[]": ["frequent urination", "straining to urinate", "blood in urine"],
                "additional_symptoms": "Cat crying when using litter box, spending more time there",
                "symptom_duration": "2-4 weeks",
                "severity": "severe",
                "recent_changes": "Recently switched to new litter brand",
                "previous_treatment": "Increased water intake as suggested online"
            }
        }
    ]
    
    # Base URL for local testing
    base_url = "http://localhost:5000"
    
    for i, case in enumerate(demo_cases, 1):
        print(f"\n📋 Demo Case {i}: {case['name']}")
        print("-" * 40)
        
        try:
            # Make request to specific disease prediction endpoint
            response = requests.post(
                f"{base_url}/predict/specific_disease",
                data=case['data'],
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('success'):
                    prediction = result['prediction']
                    print(f"✅ Prediction successful!")
                    print(f"🎯 Disease: {prediction['disease']}")
                    print(f"📊 Confidence: {prediction.get('confidence', 0.8) * 100:.1f}%")
                    print(f"📝 Description: {prediction['description']}")
                    
                    if prediction.get('alternative_diseases'):
                        print(f"\n🔄 Alternative Possibilities:")
                        for alt in prediction['alternative_diseases']:
                            print(f"   • {alt['disease']} ({alt.get('confidence', 0.6) * 100:.1f}%)")
                    
                    print(f"\n💊 Treatment Recommendations:")
                    treatment = prediction.get('treatment', {})
                    
                    if treatment.get('immediate_actions'):
                        print(f"   Immediate Actions:")
                        for action in treatment['immediate_actions']:
                            print(f"   • {action}")
                    
                    print(f"\n👨‍⚕️ Vet Consultation: {treatment.get('vet_consultation', 'Recommended')}")
                    
                else:
                    print(f"❌ Prediction failed: {result.get('error', 'Unknown error')}")
            
            elif response.status_code == 401:
                print("🔒 Authentication required - Please login first")
                print("   You can test this by logging into the web interface first")
            
            else:
                print(f"❌ Request failed with status {response.status_code}")
                print(f"   Response: {response.text}")
        
        except requests.exceptions.ConnectionError:
            print("🔌 Connection error - Make sure the Flask app is running on localhost:5000")
            print("   Run: python app.py")
        
        except requests.exceptions.Timeout:
            print("⏰ Request timeout - The AI prediction might be taking too long")
        
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print(f"\n🎯 Demo completed!")
    print(f"\nTo test manually:")
    print(f"1. Start the Flask app: python app.py")
    print(f"2. Login to the web interface at http://localhost:5000")
    print(f"3. Navigate to 'Specific Disease Prediction' from the dashboard")
    print(f"4. Fill out the form with animal information and symptoms")
    print(f"5. Get a detailed, specific disease prediction!")


def test_api_structure():
    """Test the API structure and response format"""
    
    print("\n🔧 API Structure Test")
    print("=" * 30)
    
    # Test data
    test_data = {
        "animal_type": "dog",
        "animal_age": "2 years",
        "symptoms[]": ["vomiting", "lethargy"],
        "severity": "mild"
    }
    
    print("📋 Test Request Structure:")
    print(json.dumps(test_data, indent=2))
    
    print("\n📋 Expected Response Structure:")
    expected_response = {
        "success": True,
        "prediction": {
            "disease": "Specific Disease Name",
            "confidence": 0.85,
            "description": "Detailed description of the disease",
            "alternative_diseases": [
                {
                    "disease": "Alternative Disease",
                    "confidence": 0.65,
                    "description": "Brief description"
                }
            ],
            "treatment": {
                "immediate_actions": ["Action 1", "Action 2"],
                "treatment_plan": ["Step 1", "Step 2"],
                "vet_consultation": "When to see a vet"
            },
            "risk_factors": ["Factor 1", "Factor 2"],
            "prognosis": "Expected outcome"
        }
    }
    
    print(json.dumps(expected_response, indent=2))


if __name__ == "__main__":
    print("🐾 Welcome to PashuAarogyam Specific Disease Prediction Demo!")
    print("\nThis demo will test the new specific disease prediction feature.")
    print("Make sure your Flask app is running before proceeding.")
    
    choice = input("\nChoose an option:\n1. Run demo cases\n2. Show API structure\n3. Both\nEnter choice (1-3): ").strip()
    
    if choice == "1":
        demo_specific_prediction()
    elif choice == "2":
        test_api_structure()
    elif choice == "3":
        test_api_structure()
        demo_specific_prediction()
    else:
        print("Invalid choice. Running full demo...")
        test_api_structure()
        demo_specific_prediction()
    
    print("\n🎉 Thank you for testing PashuAarogyam!")