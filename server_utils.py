# utils.py
# Utility functions for the server


def hide_key_in_image(image_path, large_shift)->bytes:
    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()
        
        hidden_message = f"KEY{{{large_shift}}}".encode('utf-8')
        modified_data = image_data + hidden_message
        
        print("Key hidden in image. Returning modified data.")
        return modified_data
    except Exception as e:
        print(f"Error in hide_key_in_image: {e}")
        raise