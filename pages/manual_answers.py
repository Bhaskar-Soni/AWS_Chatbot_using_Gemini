import random

# Function to reply Hi, Hello
def hi_response(query):
    greetings = ["hi", "hello", "hallo"]
    responses = [
        "Hi, How are you today!",
        "Hi, How was your day going so far!",
        "Hi, How may I help you!",
        "Hi, You can ask me any tech questions!",
        "Hi, You can use help by simply typing help!",
        "Hi, How can I assist you today?"
    ]
    
    if any(greeting in query.lower() for greeting in greetings):
        response_text = random.choice(responses)
        return response_text
    return None

# Function to reply who developed or created the chatbot
def creator_response(query):
    creator_queries = ["who developed you", "who develop you", "who is your developer", "who created you", "who made you"]
    responses = [
        "I was created by Bhaskar Soni.",
        "My developer is Bhaskar Soni.",
        "I was developed by Bhaskar Soni.",
        "My creator is Bhaskar Soni."
    ]
    
    if any(creator_query in query.lower() for creator_query in creator_queries):
        response_text = random.choice(responses)
        return response_text
    return None

# Function to reply how are you
def how_are_you_response(query):
    how_are_you_queries = ["how are you?", "how are you", "how are you doing"]
    responses = [
        "I'm just a program, so I don't have feelings, but I'm here and ready to help you! How can I assist you today?",
        "I'm doing great, thank you! How can I assist you today?",
        "I'm here and ready to help! How can I assist you today?",
        "I'm here and ready to assist you! What can I help you with today?",
        "I'm here to help! How can I assist you today?"
    ]
    
    if any(how_are_you_query in query.lower() for how_are_you_query in how_are_you_queries):
        response_text = random.choice(responses)
        return response_text
    return None

# Function to reply what's up 
def whats_up_response(query):
    whats_up_queries = ["what’s up?", "what’s up", "how are you doing"]
    responses = [
        "Not much, just here and ready to help you! What can I assist you with today?",
        "Not much! How can I assist you today?",
        "I'm here and ready to help! What can I do for you today?",
        "Not much, just here and ready to assist you! What do you need help with today?",
        "Nothing much! How can I assist you today?"
    ]
    
    if any(whats_up_query in query.lower() for whats_up_query in whats_up_queries):
        response_text = random.choice(responses)
        return response_text
    return None

# Function to reply age related questions
def age_response(query):
    age_queries = ["how old are you?", "how old are you", "what’s your age?", "what’s your age"]
    responses = [
        f"I exist purely as a program, so I don't have an age in the traditional sense, but I was developed by Bhaskar Soni in 2024. How may I help you today?",
        f"I don't have an age, as I'm just a program designed to assist you with information and tasks. I was developed by Bhaskar Soni in 2024. How can I help you today?"
    ]
    
    if any(age_query in query.lower() for age_query in age_queries):
        response_text = random.choice(responses)
        return response_text
    return None