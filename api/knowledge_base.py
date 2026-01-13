# api/knowledge_base.py
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

# Load embedding model
model = SentenceTransformer('all-MiniLM-L6-v2')

# Company knowledge documents
company_docs = [
    "Hads_XK is the company that developed me, specializing in general assistance, PDF analysis, and data analysis support. I was built to guide and help professionals in their careers.",
    "The 'X' in Hads_XK represents 'eXcellence', symbolizing the company's commitment to high-quality AI solutions and professional guidance.",
    "Hads_XK stands for: Hads (the developer), X (eXcellence), K (Knowledge). This represents the company's dedication to providing excellent AI assistance and professional guidance."
]

# Create embeddings
embeddings = model.encode(company_docs)

# Build FAISS index
dimension = embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(np.array(embeddings))

# Search function
def search_knowledge(query):
    query_vec = model.encode([query])
    D, I = index.search(np.array(query_vec), k=1)
    matched_doc = company_docs[I[0][0]]

    # Only return relevant info for certain keywords
    trigger_keywords = [
        "developer", "who developed", "company", "creator", "origin",
        "X", "K", "meaning of X", "meaning of K", "Hads_XK", "what does Hads_XK stand for"
    ]
    if any(keyword.lower() in query.lower() for keyword in trigger_keywords):
        return matched_doc
    return None
