import React, { useContext, useEffect } from "react";
import Hero from "../components/Hero";
import { Vacancies } from "../components/Vacancies";
import { Works } from "../components/Works";
import { Popular } from "../components/Popular";
import { Jobs } from "../components/Jobs";
import { Testimonial } from "../components/Testimonial";
import { AppContext } from "../context/AppContext";

const Home = () => {
  const { setquery } = useContext(AppContext);
  useEffect(() => {
    setquery("");
  }, []);
  return (
    <div>
      <Hero />
      <Vacancies />
      <Works />
      <Popular />
      <Jobs />
      <Testimonial />
    </div>
  );
};

export default Home;
