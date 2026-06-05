
from dataclasses import dataclass

# 1. Объявляем наш dataclass (аналог case class в Scala / data class в Kotlin)
# Значение по умолчанию для name задается через знак "="
@dataclass
class Greet:
    name: str = "Alex"
    
    # Функция внутри класса (первым аргументом ВСЕГДА идет self)
    def say(self, guest_name: str):
        # f-строка: переменные вставляются внутрь фигурных скобок { }
        print(f"Hello world! Hello {guest_name}")

    def say2(self, guest_name: str):
        # self.name берется из класса, guest_name — из параметров функции
        print(f"Hello world! Меня зовут {self.name}, а тебя зовут {guest_name}!")


# 2. Точка входа в программу 
# В Python принято проверять, запущен ли файл напрямую, через специальное условие:
if __name__ == "__main__":
    
    # Создаем объект класса (используются значения по умолчанию)
    greeter = Greet()
    
    # Вызываем метод класса
    greeter.say("Ivan") 
    # Выведет: Hello world! Hello Ivan

    # Вариант 1: Используем имя по умолчанию ("Alex")
    greeter1 = Greet()
    greeter1.say2("Ivan") 
    # Выведет: Hello world! Меня зовут Alex, а тебя зовут Ivan!

    # Вариант 2: Передаем в конструктор свое имя ("Мария")
    greeter2 = Greet(name="Мария")
    greeter2.say2("Петр")
    # Выведет: Hello world! Меня зовут Мария, а тебя зовут Петр!


// Главные особенности Python в этом примере:
// - Ключевое слово def используется для создания функций (как в Scala).
// - Внутри методов класса обязательно нужно писать self первым аргументом, а при вызове свойств класса обращаться к ним через self.name.
// - Конструкция if __name__ == "__main__": — это стандартный для Python аналог функции main(). Код внутри нее выполнится только тогда, когда вы запустите этот файл напрямую.


//

