package main
import "BirdQuery";
import "fmt";

func main() {
  var bqh, err = BirdQuery.Init("query.dump")
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println("Find 192.168.42.42/32:")
  fmt.Println(bqh.Find("192.168.42.42/32"))
  fmt.Println("FindAll 192.168.42.42:")
  fmt.Println(bqh.FindAll("192.168.42.42"))
  fmt.Println(bqh.FindAll("192.168.42.42/32"))
  fmt.Println(bqh.Find("192.168.42.42"))
  bqh.Cleanup()
}
