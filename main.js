
const schoolLinks = document.querySelectorAll('.school-link');
const schoolContent = document.querySelector('#school-content');

schoolContent.querySelectorAll('.school-info').forEach(info => {
info.style.display = 'none';
});
document.querySelector('#school-A').style.display = 'block';


schoolLinks.forEach(link => {
  link.addEventListener('click', e => {
    const school = e.target.dataset.school;
    const selectedSchool = document.querySelector(`#school-${school}`);

    schoolContent.querySelectorAll('.school-info').forEach(info => {
      info.style.display = 'none';
    });
    selectedSchool.style.display = 'block';
  });
});
