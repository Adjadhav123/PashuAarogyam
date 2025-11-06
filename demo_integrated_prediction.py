#!/usr/bin/env python3
"""
Demo script for testing the new Integrated Disease Prediction feature
This script demonstrates the improved image + symptoms correlation analysis
"""

import requests
import json
import os

def test_integrated_prediction():
    """Test the new integrated prediction feature"""
    
    print("🔬 PashuAarogyam - Integrated Disease Prediction Demo")
    print("=" * 60)
    print("Testing the new feature that combines image analysis with symptom assessment")
    print("for more accurate disease predictions.\n")
    
    # Demo test cases
    test_cases = [
        {
            "name": "Cattle with Respiratory Issues + Visual Signs",
            "description": "Testing image + symptom correlation for respiratory disease",
            "data": {
                "animal_type": "cattle",
                "animal_age": "4 years",
                "animal_weight": "500 kg",
                "animal_breed": "Holstein",
                "symptoms[]": ["coughing", "difficulty breathing", "nasal discharge", "fever", "lethargy"],
                "additional_symptoms": "Animal appears to be mouth breathing and has thick nasal discharge",
                "symptom_duration": "3-7 days",
                "severity": "moderate",
                "recent_changes": "Recently introduced to new pasture area with other cattle",
                "previous_treatment": "Isolated animal and provided fresh water"
            },
            "expected_correlation": "Visual breathing difficulty should correlate with reported respiratory symptoms"
        },
        {
            "name": "Dog with Skin Issues + Visual Confirmation",
            "description": "Testing skin condition detection through image + symptom analysis",
            "data": {
                "animal_type": "dog",
                "animal_age": "6 years",
                "animal_weight": "30 kg",
                "animal_breed": "Golden Retriever",
                "symptoms[]": ["scratching", "hair loss", "skin irritation", "red patches"],
                "additional_symptoms": "Constant scratching especially at night, seems uncomfortable",
                "symptom_duration": "1-2 weeks",
                "severity": "moderate",
                "recent_changes": "Started using new shampoo 3 weeks ago",
                "previous_treatment": "Applied aloe vera gel as suggested by neighbor"
            },
            "expected_correlation": "Visual skin redness and hair loss should support reported scratching symptoms"
        },
        {
            "name": "Cat with Behavioral + Physical Symptoms",
            "description": "Testing comprehensive analysis of behavioral and physical signs",
            "data": {
                "animal_type": "cat",
                "animal_age": "8 years",
                "animal_weight": "4 kg",
                "animal_breed": "Maine Coon",
                "symptoms[]": ["hiding behavior", "loss of appetite", "lethargy", "changes in litter box habits"],
                "additional_symptoms": "Cat has been hiding under the bed for 2 days, won't come out even for favorite treats",
                "symptom_duration": "2-4 weeks",
                "severity": "severe",
                "recent_changes": "New baby in the household, also changed litter brand",
                "previous_treatment": "Tried different foods and treats to encourage eating"
            },
            "expected_correlation": "Visual signs of stress/illness should correlate with behavioral changes"
        }
    ]
    
    # Base URL for testing
    base_url = "http://localhost:5000"
    
    print("🧪 Running Test Cases:")
    print("-" * 40)
    
    for i, case in enumerate(test_cases, 1):
        print(f"\n📋 Test Case {i}: {case['name']}")
        print(f"📝 Description: {case['description']}")
        print(f"🎯 Expected: {case['expected_correlation']}")
        print("-" * 30)
        
        try:
            # Test the integrated prediction endpoint
            response = requests.post(
                f"{base_url}/predict/integrated",
                data=case['data'],
                timeout=45  # Longer timeout for AI processing
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('success'):
                    prediction = result['prediction']
                    
                    print(f"✅ Prediction successful!")
                    print(f"🎯 Primary Diagnosis: {prediction['primary_diagnosis']}")
                    print(f"📊 Confidence: {prediction.get('confidence_score', 0.8) * 100:.1f}%")
                    print(f"🔬 Analysis Type: {prediction.get('analysis_type', 'Symptoms Only')}")
                    print(f"🖼️ Image Analyzed: {'Yes' if result.get('has_image') else 'No'}")
                    
                    # Show correlation analysis if available
                    if prediction.get('image_symptom_correlation'):
                        print(f"🔗 Symptom-Image Correlation: {prediction['image_symptom_correlation']}")
                    
                    # Show severity assessment
                    print(f"⚠️ Severity: {prediction.get('severity_assessment', 'Not specified')}")
                    
                    # Show urgency
                    urgency = prediction.get('treatment_recommendations', {}).get('veterinary_urgency', 'Not specified')
                    print(f"🚨 Veterinary Urgency: {urgency}")
                    
                    # Show top immediate actions
                    immediate_actions = prediction.get('treatment_recommendations', {}).get('immediate_actions', [])
                    if immediate_actions:
                        print(f"🚑 Top Immediate Actions:")
                        for action in immediate_actions[:2]:  # Show first 2 actions
                            print(f"   • {action}")
                    
                else:
                    print(f"❌ Prediction failed: {result.get('error', 'Unknown error')}")
            
            elif response.status_code == 401:
                print("🔒 Authentication required")
                print("   Please login to the web interface first to test this feature")
                break
            
            else:
                print(f"❌ Request failed with status {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
        
        except requests.exceptions.ConnectionError:
            print("🔌 Connection error - Make sure the Flask app is running")
            print("   Start with: python app.py")
            break
        
        except requests.exceptions.Timeout:
            print("⏰ Request timeout - AI analysis might be taking longer than expected")
        
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print(f"\n🎉 Demo completed!")
    
    # Show feature benefits
    print(f"\n🌟 Key Benefits of Integrated Prediction:")
    print(f"   • Combines visual analysis with symptom assessment")
    print(f"   • Provides symptom-image correlation analysis") 
    print(f"   • More accurate confidence scores")
    print(f"   • Comprehensive treatment recommendations")
    print(f"   • Works with or without images")
    
    print(f"\n🚀 To test manually:")
    print(f"   1. Start Flask app: python app.py")
    print(f"   2. Login at http://localhost:5000")
    print(f"   3. Click 'Integrated AI Prediction' on dashboard")
    print(f"   4. Upload an animal image (optional)")
    print(f"   5. Select symptoms and provide details")
    print(f"   6. Get comprehensive prediction with correlation analysis!")


def show_api_comparison():
    """Show comparison between old and new prediction APIs"""
    
    print("\n🔄 API Evolution Comparison")
    print("=" * 40)
    
    print("📊 Old Enhanced AI Prediction:")
    print("   • Separate image and symptom analysis")
    print("   • Basic correlation")
    print("   • Limited symptom context")
    print("   • General treatment advice")
    
    print("\n🚀 New Integrated Prediction:")
    print("   • Combined image + symptom analysis")
    print("   • Advanced correlation assessment")
    print("   • Comprehensive medical history")
    print("   • Specific treatment recommendations")
    print("   • Veterinary urgency assessment")
    print("   • Prevention advice")
    
    print("\n📋 Request Structure (New):")
    example_request = {
        "animal_type": "cattle",
        "animal_age": "3 years",
        "animal_weight": "450 kg",
        "animal_breed": "Holstein",
        "symptoms[]": ["coughing", "nasal discharge"],
        "additional_symptoms": "Mouth breathing observed",
        "symptom_duration": "3-7 days",
        "severity": "moderate",
        "recent_changes": "Moved to new pasture",
        "previous_treatment": "Isolated and monitored",
        "image": "animal_photo.jpg"
    }
    
    print(json.dumps(example_request, indent=2))
    
    print("\n📋 Response Structure (New):")
    example_response = {
        "success": True,
        "prediction": {
            "primary_diagnosis": "Bovine Respiratory Disease Complex",
            "confidence_score": 0.87,
            "diagnostic_reasoning": "Visual breathing difficulty correlates with reported symptoms...",
            "image_symptom_correlation": "Observed mouth breathing supports respiratory distress...",
            "severity_assessment": "Moderate - requires veterinary attention within 24 hours",
            "treatment_recommendations": {
                "immediate_actions": ["Isolate animal", "Provide fresh water"],
                "veterinary_urgency": "within 24 hours"
            },
            "analysis_type": "Image + Symptoms Analysis",
            "image_analyzed": True
        },
        "has_image": True,
        "image_analysis_available": True
    }
    
    print(json.dumps(example_response, indent=2))


if __name__ == "__main__":
    print("🐾 Welcome to the Integrated Disease Prediction Demo!")
    print("\nThis demo tests the improved prediction system that analyzes")
    print("both animal images AND symptoms together for better accuracy.")
    
    choice = input("\nChoose option:\n1. Run test cases\n2. Show API comparison\n3. Both\nEnter (1-3): ").strip()
    
    if choice == "1":
        test_integrated_prediction()
    elif choice == "2":
        show_api_comparison()
    elif choice == "3":
        show_api_comparison()
        test_integrated_prediction()
    else:
        print("Running full demo...")
        show_api_comparison()
        test_integrated_prediction()
    
    print("\n✨ Thank you for testing the Integrated Disease Prediction feature!")
    print("This new system provides more accurate predictions by correlating")
    print("visual findings with reported symptoms for comprehensive analysis.")