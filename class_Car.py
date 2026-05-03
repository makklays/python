
class Car:
  # конструктор класса 
  def __init__(self, brand, model, year):
    self.brand = brand
    self.model = model
    self.year = year

  def display_info(self):
    print(f"Автомобиль: {self.brand} {self.model}, год выпуска {self.year}")

# Создание объектов (экземпляров класса) 
car1 = Car("Toyota", "Corolla", 2022)
car2 = Car("Tesla", "Model 3", 2024)

# Вызов метода объектов 
car1.display_info() # Выведет: Автомобиль: Toyota Corolla, год выпуска 2022 
car2.display_info() # Выведет: Автомобиль: Tesla Model 3, год выпуска 2024 

