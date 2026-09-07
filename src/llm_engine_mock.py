import random
import json

def get_mock_llm_mutation(previous_score=None, previous_mutation=None):
    """
    Simula una risposta di un LLM.
    Riceve il punteggio del tentativo precedente e suggerisce una nuova mutazione..
    Ritorna una stringa JSON.
    """
    
    possible_mutations = [
        {"mutation_type": "mutate_tcp_flags", "value": "S"},
        {"mutation_type": "mutate_tcp_flags", "value": "A"},
        {"mutation_type": "mutate_ip_ttl", "value": 128},
        {"mutation_type": "mutate_tcp_window_size", "value": 1024},
        {"mutation_type": "mutate_source_port", "value": 54321}
    ]

    selected_mutation = random.choice(possible_mutations)

    #Simula il ragionamento del LLM.
    response = {
        "reasoning": f"Analizzando il punteggio precedente ({previous_score}). Testiamo un approccio diverso: {selected_mutation['mutation_type']}.",
        "mutation": selected_mutation
    }

    return json.dumps(response)
