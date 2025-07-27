import React from "react";
import { assets } from "../assets/assets";
import { Testimonial } from "../components/Testimonial";

const About = () => {
  return (
    <div className="py-16 px-4 max-w-7xl mx-auto ">
      <div className="grid grid-cols-2 gap-4 mt-10 justify-items-center">
        {/* left section  */}
        <div>
          <img src={assets.hero_img} alt="" />
        </div>
        {/* right section  */}
        <div>
          <h2 className="text-3xl font-semibold text-gray-800">
            Our Job Portal
          </h2>
          <p className="text-gray-600 mb-4 leading-relaxed">
            Lorem ipsum dolor sit amet consectetur, adipisicing elit. Cum eaque
            voluptatibus impedit, consequuntur temporibus adipisci neque nobis
            illum beatae, aspernatur accusamus pariatur est vero, dolor quisquam
            ipsa deleniti saepe. Quas. Lorem ipsum dolor sit, amet consectetur
            adipisicing elit. Ad cupiditate sapiente, libero labore omnis
            tempore dolore suscipit quos voluptatum porro dicta maxime officia
            atque, hic quidem quod expedita saepe sit. Lorem ipsum dolor sit
            amet consectetur, adipisicing elit. Nesciunt, vel veniam ipsum
            cupiditate ipsa doloremque. Voluptatum hic temporibus, tempore
            provident blanditiis, deserunt reiciendis, adipisci non eligendi
            quasi incidunt maiores est? Esse nam mollitia molestias cupiditate,
            perferendis fugiat! Aspernatur laudantium minima possimus. Atque sed
            accusamus libero ea architecto culpa dolorem, voluptatem cupiditate
            eum commodi, ratione, natus amet saepe totam animi quae.
          </p>
        </div>
      </div>
      <div className="mt-12 bg-gray-100 rounded-xl p-6 shadow-inner">
        <h3 className="text-2xl •text-gray-700 mb-3 font-semibold">
          Why Us !!!
        </h3>
        <p className="text-gray-600 leading-relaxed">
          Thousands Of verified listings<br></br> Lorem ipsum dolor sit amet
          consectetur adipisicing elit. Cumque sunt magni, animi aspernatur
          autem deserunt illum quidem. Nesciunt cum doloribus perspiciatis optio
          architecto ea aperiam id nam quas? Quaerat, ratione.
        </p>
        <Testimonial />
      </div>
    </div>
  );
};

export default About;
