
import tkinter as tk

def on_click():
    label.config(text="Привет, мир!")

# Создаем главное окно
window = tk.Tk()
window.title("Мое первое GUI приложение")
window.geometry("400x200")

# Добавляем текстовую метку
label = tk.Text(window)  # Ошибка исправлена: текстовое поле
label = tk.Label(window, text="Нажмите кнопку ниже", font=("Arial", 14))
label.pack(pady=20)

# Добавляем кнопку
button = tk.Button(window, text="Нажми меня", command=on_click)
button.pack()

# Запускаем бесконечный цикл обработки событий
window.mainloop()


//

