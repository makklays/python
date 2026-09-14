
class Tennis:
  
  def __init__(self, shot: int):
    self.shot = shot
    
  def is_good_shot(self) -> None:
    if self.shot == 1:
      print(f"You have a good shoot = {self.shot} !")
    else: 
      print(f"You have no good shoot = {self.shot} !")
      
  def get_good_shot(self) -> bool:
    # Метод возвращает True или False
    return self.shot == 1

# Пример использования:
game = Tennis(shot=1)
if game.get_good_shot():
    print("Отличный удар!")

