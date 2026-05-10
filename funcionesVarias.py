from collections import defaultdict

def construir_arbol(comentarios):
    hijos = defaultdict(list)

    # Agrupar hijos por parent
    for c in comentarios.values():
        hijos[c["parent"]].append(c)

    # Función recursiva
    def agregar_respuestas(comentario):
        comentario["respuestas"] = [
            agregar_respuestas(hijo)
            for hijo in hijos[comentario["id"]]
        ]
        return comentario

    # Solo raíces
    arbol = [
        agregar_respuestas(c)
        for c in hijos[0]
    ]

    return arbol

