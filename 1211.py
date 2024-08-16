import numpy as np
from sklearn import datasets
from sklearn.linear_model import Perceptron
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

# preparazione dei dati
iris = datasets.load_iris()
X = iris.data[:, [2, 3]]
y = iris.target
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)

# addestramento del modello
ppn = Perceptron(max_iter=40, tol=0.001, eta0=0.01, random_state=0)
ppn.fit(X_train, y_train)

# verifica accuratezza del modello
y_pred = ppn.predict(X_test)
print(accuracy_score(y_test, y_pred))