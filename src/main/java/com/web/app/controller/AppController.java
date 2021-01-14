package com.web.app.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AppController {

    @GetMapping("/")
    public String home(){
        return "Hola Mundo GetMapping";
    }

    @PostMapping("/")
    public String homepost(){
        return "Hola Mundo PostMapping";
    }

    @RequestMapping(value = "/homerequest")
    public String homeRequest(){
        return "Hola Mundo RequestMapping";
    }

    @GetMapping("/home/{id}")
    public String homepath(@PathVariable("id") int id){
        return "Hola Mundo Get Controller PathVariable = " + id;
    }

    @GetMapping({"/home/optional", "/home/optional/{id}"})
    public String getFooByOptionalId(@PathVariable(value="id", required = false) String id){
        return "Hola Mundo Get Optional PathVariable ID: " + id;
    }

    @GetMapping("/homerequestparam")
    public String getFooByIdUsingQueryParam(
            @RequestParam(value = "id", required = false, defaultValue = "0") Integer id) {
        return "Hola Mundo PostMapping RequestParam ID: " + id;
    }

    @PostMapping("/homepostbody")
    public String postBody(@RequestBody(required = false) String fullName) {
        return "Hello " + fullName;
    }
}
