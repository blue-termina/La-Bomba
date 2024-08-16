# Importa le librerie necessarie
import numpy as np
from sklearn.linear_model import LinearRegression

# Dati di esempio (sostituiscili con i tuoi dati reali)
X = np.array([1, 2, 3, 4, 5]).reshape(-1, 1)  # Variabili indipendenti
y = np.array([2, 4, 5, 4, 5])  # Variabile dipendente (obiettivo)

# Crea un modello di regressione lineare
model = LinearRegression()

# Addestra il modello con i dati
model.fit(X, y)

# Ora il modello ha appreso dai dati e può fare previsioni
# Ad esempio, puoi prevedere il valore per una nuova variabile indipendente:
new_x = np.array([6]).reshape(-1, 1)
prediction = model.predict(new_x)

print("Previsione:", prediction)
