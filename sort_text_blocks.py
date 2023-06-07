#! /usr/bin/env python

def sort_blocks(text):
    blocks = text.strip().split('\n\n')  # Разделение блоков по пустой строке
    sorted_blocks = sorted(blocks, key=lambda x: x.split('\n')[0])  # Сортировка блоков по первой строке

    sorted_text = '\n\n'.join(sorted_blocks)  # Объединение отсортированных блоков обратно в текст
    return sorted_text

# Пример использования
text = """
Блок 3:
Это первая строка блока 3.
Это вторая строка блока 3.

Блок 1:
Это первая строка блока 1.
Это вторая строка блока 1.

Блок 2:
Это первая строка блока 2.
Это вторая строка блока 2.
"""

sorted_text = sort_blocks(text)
print(sorted_text)
